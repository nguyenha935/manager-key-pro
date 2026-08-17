package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Key mirrors one row of the keys table. Quota lives on the key, not the user.
type Key struct {
	ID               string
	UserID           string
	KeyHash          string
	KeyCipher        []byte
	KeyNonce         []byte
	Prefix           string
	Name             string
	Status           string
	QuotaKind        string
	QuotaScope       string
	QuotaAmount      int64
	QuotaUsed        int64
	PeriodStart      int64
	PeriodEnd        int64
	ExpiresAt        int64
	OverflowToWallet bool
	PackageID        string
	AllowedModels    []string
	AllowedProviders []string
	IPAllowlist      []string
	RPM              int
	LogMode          string
	PricingOverrides string
	CreatedAt        int64
	UpdatedAt        int64
	LastUsedAt       int64
}

// IsActive reports whether the key can authenticate and spend.
func (k Key) IsActive() bool { return k.Status == "active" }

// HasQuota reports whether the key can still spend from its own quota before
// overflowing to the wallet. Unlimited keys always report true.
func (k Key) HasQuota() bool {
	if k.QuotaKind == "unlimited" {
		return true
	}
	return k.QuotaUsed < k.QuotaAmount
}

// QuotaRemaining returns how much is left. Negative means already over.
func (k Key) QuotaRemaining() int64 {
	if k.QuotaKind == "unlimited" {
		return 1<<62 - 1 // large sentinel
	}
	return k.QuotaAmount - k.QuotaUsed
}

// KeysRepo reads and writes key rows.
type KeysRepo struct{ db *DB }

// Keys returns the key repository.
func (d *DB) Keys() *KeysRepo { return &KeysRepo{db: d} }

const keyColumns = `id, user_id, key_hash, key_cipher, key_nonce, prefix, name, status,
	quota_kind, quota_scope, quota_amount, quota_used,
	COALESCE(period_start,0), COALESCE(period_end,0), expires_at, overflow_to_wallet,
	COALESCE(package_id,''), COALESCE(allowed_models,'[]'), COALESCE(allowed_providers,'[]'),
	COALESCE(ip_allowlist,'[]'), rpm, COALESCE(log_mode,''), COALESCE(pricing_overrides,''),
	created_at, updated_at, COALESCE(last_used_at,0)`

func scanKey(row interface{ Scan(...any) error }) (Key, error) {
	var k Key
	var allowedModelsJSON, allowedProvidersJSON, ipAllowlistJSON string
	var overflow int
	errScan := row.Scan(&k.ID, &k.UserID, &k.KeyHash, &k.KeyCipher, &k.KeyNonce, &k.Prefix, &k.Name, &k.Status,
		&k.QuotaKind, &k.QuotaScope, &k.QuotaAmount, &k.QuotaUsed,
		&k.PeriodStart, &k.PeriodEnd, &k.ExpiresAt, &overflow,
		&k.PackageID, &allowedModelsJSON, &allowedProvidersJSON,
		&ipAllowlistJSON, &k.RPM, &k.LogMode, &k.PricingOverrides,
		&k.CreatedAt, &k.UpdatedAt, &k.LastUsedAt)
	if errors.Is(errScan, sql.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if errScan != nil {
		return Key{}, fmt.Errorf("scan key: %w", errScan)
	}
	k.OverflowToWallet = overflow != 0
	k.AllowedModels = decodeJSONList(allowedModelsJSON)
	k.AllowedProviders = decodeJSONList(allowedProvidersJSON)
	k.IPAllowlist = decodeJSONList(ipAllowlistJSON)
	return k, nil
}

// CreateKeyInput bundles the parameters for creating a key.
type CreateKeyInput struct {
	UserID           string
	KeyHash          string
	KeyCipher        []byte
	KeyNonce         []byte
	Prefix           string
	Name             string
	QuotaKind        string
	QuotaScope       string
	QuotaAmount      int64
	ExpiresAt        int64  // -1 = never
	PackageID        string // empty when admin-created without a package
	AllowedModels    []string
	AllowedProviders []string
	IPAllowlist      []string
	RPM              int
}

// Create inserts a key with the supplied quota and cipher. The caller must hash
// and encrypt the plaintext key before calling this.
func (r *KeysRepo) Create(input CreateKeyInput) (Key, error) {
	if input.Name == "" {
		input.Name = "Unnamed key"
	}
	if input.QuotaKind == "" {
		input.QuotaKind = "credit"
	}
	if input.QuotaScope == "" {
		input.QuotaScope = "lifetime"
	}
	if input.RPM <= 0 {
		input.RPM = 60
	}
	id := newID("key")
	now := Now()
	_, errExec := r.db.sql.Exec(`
		INSERT INTO keys (id, user_id, key_hash, key_cipher, key_nonce, prefix, name, status,
			quota_kind, quota_scope, quota_amount, quota_used, expires_at, overflow_to_wallet,
			package_id, allowed_models, allowed_providers, ip_allowlist, rpm,
			created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'active',
			?, ?, ?, 0, ?, 0,
			?, ?, ?, ?, ?,
			?, ?)`,
		id, input.UserID, input.KeyHash, input.KeyCipher, input.KeyNonce, input.Prefix, input.Name,
		input.QuotaKind, input.QuotaScope, input.QuotaAmount, input.ExpiresAt,
		nullIfEmpty(input.PackageID), encodeJSONList(input.AllowedModels),
		encodeJSONList(input.AllowedProviders), encodeJSONList(input.IPAllowlist), input.RPM,
		now, now)
	if errExec != nil {
		if isUniqueViolation(errExec) {
			return Key{}, ErrDuplicate
		}
		return Key{}, fmt.Errorf("insert key: %w", errExec)
	}
	return r.ByID(id)
}

// ByID loads one key.
func (r *KeysRepo) ByID(id string) (Key, error) {
	return scanKey(r.db.sql.QueryRow(`SELECT `+keyColumns+` FROM keys WHERE id = ?`, id))
}

// ByHash loads a key for authentication. The hash is sha256(plaintext key).
func (r *KeysRepo) ByHash(keyHash string) (Key, error) {
	return scanKey(r.db.sql.QueryRow(`SELECT `+keyColumns+` FROM keys WHERE key_hash = ?`, keyHash))
}

// ListByUser returns all keys owned by the user, newest first.
func (r *KeysRepo) ListByUser(userID string, limit int) ([]Key, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, errQuery := r.db.sql.Query(
		`SELECT `+keyColumns+` FROM keys WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
		userID, limit)
	if errQuery != nil {
		return nil, fmt.Errorf("query keys: %w", errQuery)
	}
	defer rows.Close()
	var keys []Key
	for rows.Next() {
		k, errScan := scanKey(rows)
		if errScan != nil {
			return nil, errScan
		}
		keys = append(keys, k)
	}
	if errRows := rows.Err(); errRows != nil {
		return nil, fmt.Errorf("iterate keys: %w", errRows)
	}
	return keys, nil
}

// SetStatus enables, disables or bans a key.
func (r *KeysRepo) SetStatus(keyID, status string) error {
	result, errExec := r.db.sql.Exec(`UPDATE keys SET status = ?, updated_at = ? WHERE id = ?`, status, Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("set status: %w", errExec)
	}
	return requireOneRow(result)
}

// ConsumeQuota increments quota_used by delta. Callers must check HasQuota first;
// this does not enforce the limit, it only records what was spent.
func (r *KeysRepo) ConsumeQuota(keyID string, delta int64) error {
	result, errExec := r.db.sql.Exec(
		`UPDATE keys SET quota_used = quota_used + ?, updated_at = ?, last_used_at = ? WHERE id = ?`,
		delta, Now(), Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("consume quota: %w", errExec)
	}
	return requireOneRow(result)
}

// ResetPeriod zeroes quota_used and sets a new period window. For scoped quotas
// (hour, day, week, month), the billing loop calls this once the period ends.
func (r *KeysRepo) ResetPeriod(keyID string, periodStart, periodEnd int64) error {
	result, errExec := r.db.sql.Exec(
		`UPDATE keys SET quota_used = 0, period_start = ?, period_end = ?, updated_at = ? WHERE id = ?`,
		periodStart, periodEnd, Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("reset period: %w", errExec)
	}
	return requireOneRow(result)
}

// SetOverflow controls whether spending beyond the key's quota flows to the wallet.
func (r *KeysRepo) SetOverflow(keyID string, enabled bool) error {
	val := 0
	if enabled {
		val = 1
	}
	result, errExec := r.db.sql.Exec(`UPDATE keys SET overflow_to_wallet = ?, updated_at = ? WHERE id = ?`, val, Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("set overflow: %w", errExec)
	}
	return requireOneRow(result)
}

// SetLogMode pins a key's logging mode, overriding the global setting.
func (r *KeysRepo) SetLogMode(keyID, mode string) error {
	mode = strings.TrimSpace(mode)
	if mode != "" && mode != "full" && mode != "standard" && mode != "error_only" {
		return errors.New("invalid log mode")
	}
	result, errExec := r.db.sql.Exec(`UPDATE keys SET log_mode = ?, updated_at = ? WHERE id = ?`, nullIfEmpty(mode), Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("set log mode: %w", errExec)
	}
	return requireOneRow(result)
}

// Rename changes a key's display name.
func (r *KeysRepo) Rename(keyID, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Unnamed key"
	}
	result, errExec := r.db.sql.Exec(`UPDATE keys SET name = ?, updated_at = ? WHERE id = ?`, name, Now(), keyID)
	if errExec != nil {
		return fmt.Errorf("rename key: %w", errExec)
	}
	return requireOneRow(result)
}

// Delete removes a key permanently. Usage records remain for audit.
func (r *KeysRepo) Delete(keyID string) error {
	result, errExec := r.db.sql.Exec(`DELETE FROM keys WHERE id = ?`, keyID)
	if errExec != nil {
		return fmt.Errorf("delete key: %w", errExec)
	}
	return requireOneRow(result)
}
