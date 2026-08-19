package plugin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/scheduler"
	"github.com/nguyenha935/manager-key-pro/internal/store"
	"golang.org/x/crypto/argon2"
)

// ---- Key update (rename, transfer, access lists, log mode) ----

type updateKeyBody struct {
	ID               string   `json:"id"`
	Name             *string  `json:"name"`
	UserID           *string  `json:"user_id"` // admin transfer
	AllowedModels    []string `json:"allowed_models"`
	AllowedProviders []string `json:"allowed_providers"`
	IPAllowlist      []string `json:"ip_allowlist"`
	RPM              *int     `json:"rpm"`
	LogMode          *string  `json:"log_mode"`
	Overflow         *bool    `json:"overflow_to_wallet"`
	SetProviders     bool     `json:"set_providers"`
	SetModels        bool     `json:"set_models"`
	SetIP            bool     `json:"set_ip_allowlist"`
}

func mgmtUpdateKey(body []byte) ([]byte, error) {
	var in updateKeyBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.ID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "id required"})
	}
	k, errKey := app.db.Keys().ByID(in.ID)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "key not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errKey.Error()})
	}

	if in.Name != nil && strings.TrimSpace(*in.Name) != "" {
		if errRename := app.db.Keys().Rename(in.ID, *in.Name); errRename != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errRename.Error()})
		}
	}
	if in.UserID != nil && *in.UserID != k.UserID {
		// Transfer to another user; block while a reservation is open.
		var open int
		_ = app.db.SQL().QueryRow(
			`SELECT COUNT(1) FROM reservations WHERE key_id = ? AND status = 'open'`, in.ID).Scan(&open)
		if open > 0 {
			return mgmtJSON(http.StatusConflict, map[string]string{"error": "key has an open reservation; retry later"})
		}
		if _, errTarget := app.db.Users().ByID(*in.UserID); errTarget != nil {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "target user not found"})
		}
		if errTransfer := app.db.Keys().Transfer(in.ID, *in.UserID); errTransfer != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errTransfer.Error()})
		}
		audit("admin", "key.transfer", in.ID, *in.UserID, "")
	}
	if in.SetModels {
		if errSet := app.db.Keys().SetModels(in.ID, in.AllowedModels); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.SetProviders || in.SetIP {
		providers := k.AllowedProviders
		ips := k.IPAllowlist
		if in.SetProviders {
			providers = in.AllowedProviders
		}
		if in.SetIP {
			ips = in.IPAllowlist
		}
		if errSet := app.db.Keys().SetAccess(in.ID, providers, ips); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.RPM != nil {
		if errSet := app.db.Keys().SetRPM(in.ID, *in.RPM); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.LogMode != nil {
		if errSet := app.db.Keys().SetLogMode(in.ID, *in.LogMode); errSet != nil {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": errSet.Error()})
		}
	}
	if in.Overflow != nil {
		if errSet := app.db.Keys().SetOverflow(in.ID, *in.Overflow); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	audit("admin", "key.update", in.ID, k.UserID, "")
	return mgmtJSON(http.StatusOK, map[string]string{"id": in.ID, "status": "updated"})
}

// ---- Key account bindings (% share of upstream accounts) ----

func mgmtListBindings(keyID string) ([]byte, error) {
	if keyID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "key_id required"})
	}
	bindings, errList := scheduler.ListBindings(app.db, keyID)
	if errList != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errList.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{"bindings": bindings})
}

type setBindingsBody struct {
	KeyID    string             `json:"key_id"`
	Bindings []scheduler.Binding `json:"bindings"`
}

func mgmtSetBindings(body []byte) ([]byte, error) {
	var in setBindingsBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.KeyID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "key_id required"})
	}
	if errSet := scheduler.SetBindings(app.db, in.KeyID, in.Bindings); errSet != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": errSet.Error()})
	}
	audit("admin", "key.bindings", in.KeyID, "", fmt.Sprintf(`{"count":%d}`, len(in.Bindings)))
	return mgmtJSON(http.StatusOK, map[string]string{"key_id": in.KeyID, "status": "saved"})
}

// ---- User update (role, wallet mode, credit limit) ----

type updateUserBody struct {
	ID          string  `json:"id"`
	Role        *string `json:"role"`
	WalletMode  *string `json:"wallet_mode"`
	CreditLimit *int64  `json:"credit_limit"`
	Username    *string `json:"username"`
}

func mgmtUpdateUser(body []byte) ([]byte, error) {
	var in updateUserBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.ID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "id required"})
	}
	if _, errUser := app.db.Users().ByID(in.ID); errUser != nil {
		if store.IsNotFound(errUser) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errUser.Error()})
	}
	updates := map[string]any{}
	if in.Role != nil {
		if *in.Role != "user" && *in.Role != "admin" {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "role must be user or admin"})
		}
		updates["role"] = *in.Role
	}
	if in.WalletMode != nil {
		if *in.WalletMode != "prepaid" && *in.WalletMode != "postpaid" {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "wallet_mode must be prepaid or postpaid"})
		}
		updates["wallet_mode"] = *in.WalletMode
	}
	if in.CreditLimit != nil {
		updates["credit_limit"] = *in.CreditLimit
	}
	if in.Username != nil && strings.TrimSpace(*in.Username) != "" {
		updates["username"] = strings.TrimSpace(*in.Username)
	}
	for col, val := range updates {
		if _, errExec := app.db.SQL().Exec(
			`UPDATE users SET `+col+` = ? WHERE id = ?`, val, in.ID); errExec != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errExec.Error()})
		}
	}
	audit("admin", "user.update", "", in.ID, "")
	return mgmtJSON(http.StatusOK, map[string]string{"id": in.ID, "status": "updated"})
}

type resetPasswordBody struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

func mgmtResetPassword(body []byte) ([]byte, error) {
	var in resetPasswordBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.UserID == "" || in.Password == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "user_id and password required"})
	}
	hash := argon2Hash(in.Password)
	if errSet := app.db.Users().SetPassword(in.UserID, hash); errSet != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
	}
	// Revoke sessions so the old password stops working everywhere.
	if _, errExec := app.db.SQL().Exec(`DELETE FROM sessions WHERE user_id = ?`, in.UserID); errExec != nil {
		log.Printf("[mkp] revoke sessions: %v", errExec)
	}
	audit("admin", "user.reset_password", "", in.UserID, "")
	return mgmtJSON(http.StatusOK, map[string]string{"status": "updated"})
}

// argon2Hash mirrors the portal's argon2id format so both login paths accept
// passwords set from either side.
func argon2Hash(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		hex.EncodeToString(salt), hex.EncodeToString(hash))
}
