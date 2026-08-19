// Package issue is the single key-issuing + package-purchase path shared by the
// admin dashboard and the user portal (design §2.3: one issueKey() for both).
package issue

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Spec describes the quota to apply to a new or renewed key.
type Spec struct {
	Name        string
	QuotaKind   string
	QuotaScope  string
	QuotaAmount int64
	PlanType    string // lifetime | windowed
	WindowHours int64  // >0 custom window (5h / 10d presets)
	ExpiresAt   int64 // -1 = never
	RPM         int
	Models      []string
	PackageID   string
}

// Key creates one key for userID applying spec. Returns the key row and the
// plaintext (the only moment plaintext exists outside cipher storage).
func Key(db *store.DB, secretKey []byte, userID string, spec Spec, actor string) (store.Key, string, error) {
	if _, errUser := db.Users().ByID(userID); errUser != nil {
		return store.Key{}, "", fmt.Errorf("user not found")
	}
	plain, errGen := crypto.GenerateKey()
	if errGen != nil {
		return store.Key{}, "", errGen
	}
	cipher, nonce, errEnc := crypto.EncryptKey(plain, secretKey)
	if errEnc != nil {
		return store.Key{}, "", errEnc
	}
	k, errCreate := db.Keys().Create(store.CreateKeyInput{
		UserID:        userID,
		KeyHash:       crypto.HashKey(plain),
		KeyCipher:     cipher,
		KeyNonce:      nonce,
		Prefix:        crypto.Prefix(plain),
		Name:          spec.Name,
		QuotaKind:     spec.QuotaKind,
		QuotaScope:    spec.QuotaScope,
		QuotaAmount:   spec.QuotaAmount,
		PlanType:      spec.PlanType,
		WindowHours:   spec.WindowHours,
		ExpiresAt:     spec.ExpiresAt,
		PackageID:     spec.PackageID,
		AllowedModels: spec.Models,
		RPM:           spec.RPM,
	})
	if errCreate != nil {
		return store.Key{}, "", errCreate
	}
	audit(db, actor, "key.create", k.ID, userID, fmt.Sprintf(`{"name":%q,"quota_kind":%q,"quota_amount":%d}`, spec.Name, spec.QuotaKind, spec.QuotaAmount))
	return k, plain, nil
}

// BuyPackage debits the user wallet and either issues a fresh key or renews an
// existing one, all in one transaction-safe sequence (design §2.3 / §4).
// kind: "new_key" | "renew". renewKeyID is required when kind=renew.
func BuyPackage(db *store.DB, secretKey []byte, userID, packageID, kind, renewKeyID string) (orderID, keyID, plain string, err error) {
	pkg, errPkg := db.Packages().ByID(packageID)
	if errPkg != nil {
		return "", "", "", fmt.Errorf("package not found")
	}
	if kind != "new_key" && kind != "renew" {
		return "", "", "", fmt.Errorf("kind must be new_key or renew")
	}
	if kind == "renew" && renewKeyID == "" {
		return "", "", "", fmt.Errorf("key_id required for renew")
	}
	if kind == "renew" {
		k, errKey := db.Keys().ByID(renewKeyID)
		if errKey != nil || k.UserID != userID {
			return "", "", "", fmt.Errorf("key not found or not owned by you")
		}
	}

	// Debit wallet first (refuses to go below zero for prepaid).
	refID := fmt.Sprintf("order:%s:%d", packageID, store.Now())
	if _, errAdj := db.Users().AdjustBalance(userID, -pkg.PriceCredit, store.ReasonPurchase, refID, "portal", ""); errAdj != nil {
		return "", "", "", errAdj
	}

	// Compute expiry from package duration.
	expires := int64(-1)
	if pkg.DurationDays > 0 {
		expires = store.Now() + pkg.DurationDays*24*60*60*1000
	}
	var models []string
	if len(pkg.ModelsJSON) > 2 {
		_ = jsonUnmarshalList(pkg.ModelsJSON, &models)
	}
	scope := pkg.QuotaScope
	if pkg.WindowHours > 0 && scope == "lifetime" {
		// A custom window (5h / 10d) needs a cyclic scope so EnsurePeriod runs.
		scope = "day"
	}

	if kind == "renew" {
		// Extend the old key: add quota, extend expiry, reactivate.
		k, _ := db.Keys().ByID(renewKeyID)
		newAmount := k.QuotaAmount + pkg.QuotaAmount
		newExpires := expires
		if expires > 0 && k.ExpiresAt > store.Now() {
			newExpires = k.ExpiresAt + pkg.DurationDays*24*60*60*1000
		}
		if _, errExec := db.SQL().Exec(
			`UPDATE keys SET quota_amount = ?, expires_at = ?, status = 'active', updated_at = ? WHERE id = ?`,
			newAmount, newExpires, store.Now(), renewKeyID); errExec != nil {
			return "", "", "", fmt.Errorf("renew key: %w", errExec)
		}
		quotaHistory(db, renewKeyID, "renew",
			fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, k.QuotaAmount, k.ExpiresAt),
			fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, newAmount, newExpires), "user:"+userID)
		ord, errOrder := db.Orders().Create(userID, packageID, renewKeyID, "renew", pkg.PriceCredit, "paid")
		if errOrder != nil {
			return "", "", "", errOrder
		}
		return ord.ID, renewKeyID, "", nil
	}

	spec := Spec{
		Name: pkg.Name, QuotaKind: pkg.QuotaKind, QuotaScope: scope,
		QuotaAmount: pkg.QuotaAmount,
		PlanType: pkg.PlanType, WindowHours: pkg.WindowHours,
		ExpiresAt: expires, RPM: pkg.RPM,
		Models: models, PackageID: pkg.ID,
	}
	k, plainKey, errKey := Key(db, secretKey, userID, spec, "user:"+userID)
	if errKey != nil {
		return "", "", "", errKey
	}
	ord, errOrder := db.Orders().Create(userID, packageID, k.ID, "new_key", pkg.PriceCredit, "paid")
	if errOrder != nil {
		return "", "", "", errOrder
	}
	return ord.ID, k.ID, plainKey, nil
}

func audit(db *store.DB, actor, action, keyID, userID, detail string) {
	_, _ = db.SQL().Exec(
		`INSERT INTO audit_log (user_id, key_id, actor, action, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		nullStr(userID), nullStr(keyID), actor, action, detail, store.Now())
}

func quotaHistory(db *store.DB, keyID, action, beforeJSON, afterJSON, actor string) {
	_, _ = db.SQL().Exec(
		`INSERT INTO key_quota_history (key_id, action, before_json, after_json, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, keyID, action, beforeJSON, afterJSON, actor, store.Now())
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func jsonUnmarshalList(raw string, dest *[]string) error {
	return json.Unmarshal([]byte(raw), dest)
}

var _ = sql.ErrNoRows
