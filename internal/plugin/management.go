package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// managementRegister returns the routes CPA should expose under
// /v0/management/plugins/manager-key-pro/.
func managementRegister() ([]byte, error) {
	reg := map[string]any{
		"Routes": []map[string]string{
			// GET routes carry Menu so CPA also exposes them under
			// /v0/resource/plugins/manager-key-pro/ (browser-navigable, no
			// management key) for the admin dashboard to read.
			{"Method": "GET", "Path": "/keys", "Menu": "Manager Key Pro"},
			{"Method": "POST", "Path": "/keys"},
			{"Method": "GET", "Path": "/keys/:id", "Menu": "Manager Key Pro"},
			{"Method": "PATCH", "Path": "/keys/:id"},
			{"Method": "DELETE", "Path": "/keys/:id"},
			{"Method": "GET", "Path": "/keys/:id/reveal", "Menu": "Manager Key Pro"},
			{"Method": "POST", "Path": "/keys/:id/renew"},
			{"Method": "PATCH", "Path": "/keys/:id/quota"},
			{"Method": "GET", "Path": "/users", "Menu": "Manager Key Pro"},
			{"Method": "POST", "Path": "/users"},
			{"Method": "GET", "Path": "/users/:id", "Menu": "Manager Key Pro"},
			{"Method": "PATCH", "Path": "/users/:id"},
			{"Method": "POST", "Path": "/users/:id/recharge"},
			{"Method": "GET", "Path": "/users/:id/ledger", "Menu": "Manager Key Pro"},
			{"Method": "GET", "Path": "/usage", "Menu": "Manager Key Pro"},
			{"Method": "GET", "Path": "/stats", "Menu": "Manager Key Pro"},
		},
		"Resources": []map[string]string{},
	}
	raw, errMarshal := json.Marshal(reg)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal management routes: %w", errMarshal)
	}
	return okEnvelopeJSON(string(raw))
}

type managementRequest struct {
	Method  string              `json:"Method"`
	Path    string              `json:"Path"`
	Headers map[string][]string `json:"Headers"`
	Query   map[string][]string `json:"Query"`
	Body    []byte              `json:"Body"`
}

type managementResponse struct {
	StatusCode int                 `json:"StatusCode"`
	Headers    map[string][]string `json:"Headers"`
	Body       []byte              `json:"Body"`
}

func handleManagement(payload []byte) ([]byte, error) {
	if app == nil {
		return mgmtJSON(http.StatusServiceUnavailable, map[string]string{"error": "plugin not booted"})
	}
	var req managementRequest
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}
	// Strip the plugin prefix CPA may include.
	// Note: resource routes arrive as /v0/resource/plugins/<id>/<path>, management
	// routes as /v0/management/plugins/<id>/<path> — strip both.
	path := req.Path
	for _, prefix := range []string{
		"/v0/resource/plugins/manager-key-pro",
		"/v0/management/plugins/manager-key-pro",
		"/plugins/manager-key-pro",
		"/manager-key-pro",
	} {
		if strings.HasPrefix(path, prefix) {
			path = strings.TrimPrefix(path, prefix)
			break
		}
	}
	if path == "" {
		path = "/"
	}
	method := strings.ToUpper(req.Method)
	log.Printf("[mkp] management %s %s", method, path)

	switch {
	case method == "GET" && path == "/keys":
		return mgmtListKeys()
	case method == "POST" && path == "/keys":
		return mgmtCreateKey(req.Body)
	case method == "GET" && strings.HasPrefix(path, "/keys/") && strings.HasSuffix(path, "/reveal"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/keys/"), "/reveal")
		return mgmtRevealKey(id)
	case method == "GET" && strings.HasPrefix(path, "/keys/"):
		id := strings.TrimPrefix(path, "/keys/")
		return mgmtGetKey(id)
	case method == "DELETE" && strings.HasPrefix(path, "/keys/"):
		id := strings.TrimPrefix(path, "/keys/")
		return mgmtDeleteKey(id)
	case method == "POST" && strings.HasPrefix(path, "/keys/") && strings.HasSuffix(path, "/renew"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/keys/"), "/renew")
		return mgmtRenewKey(id, req.Body)
	case method == "GET" && path == "/users":
		return mgmtListUsers()
	case method == "POST" && path == "/users":
		return mgmtCreateUser(req.Body)
	case method == "POST" && strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/recharge"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/recharge")
		return mgmtRecharge(id, req.Body)
	case method == "GET" && path == "/usage":
		return mgmtListUsage()
	case method == "GET" && path == "/stats":
		return mgmtStats()
	default:
		return mgmtJSON(http.StatusNotFound, map[string]string{"error": "route not found", "path": path})
	}
}

func mgmtJSON(status int, body any) ([]byte, error) {
	raw, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal body: %w", errMarshal)
	}
	resp := managementResponse{
		StatusCode: status,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       raw,
	}
	out, errOut := json.Marshal(resp)
	if errOut != nil {
		return nil, fmt.Errorf("marshal response: %w", errOut)
	}
	return okEnvelopeJSON(string(out))
}

func mgmtListKeys() ([]byte, error) {
	// List all keys across users — admin view.
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, user_id, prefix, name, status, quota_kind, quota_scope,
			quota_amount, quota_used, expires_at, overflow_to_wallet, rpm,
			created_at, last_used_at
		FROM keys ORDER BY created_at DESC LIMIT 500`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID               string `json:"id"`
		UserID           string `json:"user_id"`
		Prefix           string `json:"prefix"`
		Name             string `json:"name"`
		Status           string `json:"status"`
		QuotaKind        string `json:"quota_kind"`
		QuotaScope       string `json:"quota_scope"`
		QuotaAmount      int64  `json:"quota_amount"`
		QuotaUsed        int64  `json:"quota_used"`
		ExpiresAt        int64  `json:"expires_at"`
		OverflowToWallet int    `json:"overflow_to_wallet"`
		RPM              int    `json:"rpm"`
		CreatedAt        int64  `json:"created_at"`
		LastUsedAt       int64  `json:"last_used_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.UserID, &r.Prefix, &r.Name, &r.Status,
			&r.QuotaKind, &r.QuotaScope, &r.QuotaAmount, &r.QuotaUsed, &r.ExpiresAt,
			&r.OverflowToWallet, &r.RPM, &r.CreatedAt, &r.LastUsedAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"keys": out})
}

func mgmtGetKey(id string) ([]byte, error) {
	k, errKey := app.db.Keys().ByID(id)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "key not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errKey.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": k.ID, "user_id": k.UserID, "prefix": k.Prefix, "name": k.Name,
		"status": k.Status, "quota_kind": k.QuotaKind, "quota_scope": k.QuotaScope,
		"quota_amount": k.QuotaAmount, "quota_used": k.QuotaUsed,
		"expires_at": k.ExpiresAt, "overflow_to_wallet": k.OverflowToWallet,
		"rpm": k.RPM, "allowed_models": k.AllowedModels,
		"created_at": k.CreatedAt, "last_used_at": k.LastUsedAt,
	})
}

type createKeyBody struct {
	UserID      string   `json:"user_id"`
	Name        string   `json:"name"`
	QuotaKind   string   `json:"quota_kind"`
	QuotaScope  string   `json:"quota_scope"`
	QuotaAmount int64    `json:"quota_amount"`
	ExpiresAt   int64    `json:"expires_at"`
	RPM         int      `json:"rpm"`
	Models      []string `json:"allowed_models"`
	Overflow    bool     `json:"overflow_to_wallet"`
}

func mgmtCreateKey(body []byte) ([]byte, error) {
	var in createKeyBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.UserID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "user_id required"})
	}
	if _, errUser := app.db.Users().ByID(in.UserID); errUser != nil {
		return mgmtJSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	if in.QuotaKind == "" {
		in.QuotaKind = "token"
	}
	if in.QuotaScope == "" {
		in.QuotaScope = "lifetime"
	}
	if in.QuotaAmount <= 0 {
		in.QuotaAmount = 1000
	}
	if in.ExpiresAt == 0 {
		in.ExpiresAt = -1
	}
	if in.RPM <= 0 {
		in.RPM = 60
	}
	if in.Name == "" {
		in.Name = "API Key"
	}

	plain, errGen := crypto.GenerateKey()
	if errGen != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errGen.Error()})
	}
	cipher, nonce, errEnc := crypto.EncryptKey(plain, app.secretKey)
	if errEnc != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errEnc.Error()})
	}
	k, errCreate := app.db.Keys().Create(store.CreateKeyInput{
		UserID:        in.UserID,
		KeyHash:       crypto.HashKey(plain),
		KeyCipher:     cipher,
		KeyNonce:      nonce,
		Prefix:        crypto.Prefix(plain),
		Name:          in.Name,
		QuotaKind:     in.QuotaKind,
		QuotaScope:    in.QuotaScope,
		QuotaAmount:   in.QuotaAmount,
		ExpiresAt:     in.ExpiresAt,
		AllowedModels: in.Models,
		RPM:           in.RPM,
	})
	if errCreate != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errCreate.Error()})
	}
	if in.Overflow {
		if errOverflow := app.db.Keys().SetOverflow(k.ID, true); errOverflow != nil {
			log.Printf("[mkp] set overflow: %v", errOverflow)
		}
	}
	// Plaintext is returned exactly once at creation. Reveal uses the cipher later.
	return mgmtJSON(http.StatusCreated, map[string]any{
		"id": k.ID, "user_id": k.UserID, "name": k.Name,
		"prefix": k.Prefix, "plain_key": plain,
		"quota_kind": k.QuotaKind, "quota_amount": k.QuotaAmount,
		"note": "Save plain_key now. It can also be revealed later via /keys/:id/reveal.",
	})
}

func mgmtRevealKey(id string) ([]byte, error) {
	k, errKey := app.db.Keys().ByID(id)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "key not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errKey.Error()})
	}
	plain, errDec := crypto.DecryptKey(k.KeyCipher, k.KeyNonce, app.secretKey)
	if errDec != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": "decrypt failed — encryption_key may have changed"})
	}
	// Audit every reveal.
	if _, errAudit := app.db.SQL().Exec(
		`INSERT INTO audit_log (user_id, key_id, actor, action, detail, created_at)
		 VALUES (?, ?, 'admin', 'key.reveal', '{}', ?)`,
		k.UserID, k.ID, store.Now()); errAudit != nil {
		log.Printf("[mkp] audit reveal: %v", errAudit)
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": k.ID, "plain_key": plain, "prefix": k.Prefix,
	})
}

func mgmtDeleteKey(id string) ([]byte, error) {
	if errDel := app.db.Keys().Delete(id); errDel != nil {
		if store.IsNotFound(errDel) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "key not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errDel.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

type renewBody struct {
	AddQuota   int64 `json:"add_quota"`
	ExtendDays int   `json:"extend_days"`
	SetExpires int64 `json:"set_expires_at"` // absolute epoch ms; 0 = ignore
}

func mgmtRenewKey(id string, body []byte) ([]byte, error) {
	var in renewBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	k, errKey := app.db.Keys().ByID(id)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "key not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errKey.Error()})
	}
	// Apply renew via raw SQL for v0.1 (KeysRepo.Renew comes later).
	newAmount := k.QuotaAmount + in.AddQuota
	newExpires := k.ExpiresAt
	if in.SetExpires != 0 {
		newExpires = in.SetExpires
	} else if in.ExtendDays > 0 {
		base := k.ExpiresAt
		if base < 0 || base < store.Now() {
			base = store.Now()
		}
		newExpires = base + int64(in.ExtendDays)*24*60*60*1000
	}
	if _, errExec := app.db.SQL().Exec(
		`UPDATE keys SET quota_amount = ?, expires_at = ?, status = 'active', updated_at = ? WHERE id = ?`,
		newAmount, newExpires, store.Now(), id); errExec != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errExec.Error()})
	}
	if _, errHist := app.db.SQL().Exec(
		`INSERT INTO key_quota_history (key_id, action, before_json, after_json, actor, created_at)
		 VALUES (?, 'renew', ?, ?, 'admin', ?)`,
		id,
		fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, k.QuotaAmount, k.ExpiresAt),
		fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, newAmount, newExpires),
		store.Now()); errHist != nil {
		log.Printf("[mkp] renew history: %v", errHist)
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": id, "quota_amount": newAmount, "expires_at": newExpires,
	})
}

func mgmtListUsers() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, username, COALESCE(telegram_id,''), role, status, balance,
			wallet_mode, credit_limit, referral_code, created_at, COALESCE(last_login_at,0)
		FROM users ORDER BY created_at DESC LIMIT 500`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID           string `json:"id"`
		Username     string `json:"username"`
		TelegramID   string `json:"telegram_id"`
		Role         string `json:"role"`
		Status       string `json:"status"`
		Balance      int64  `json:"balance"`
		WalletMode   string `json:"wallet_mode"`
		CreditLimit  int64  `json:"credit_limit"`
		ReferralCode string `json:"referral_code"`
		CreatedAt    int64  `json:"created_at"`
		LastLoginAt  int64  `json:"last_login_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.Username, &r.TelegramID, &r.Role, &r.Status,
			&r.Balance, &r.WalletMode, &r.CreditLimit, &r.ReferralCode,
			&r.CreatedAt, &r.LastLoginAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"users": out})
}

type createUserBody struct {
	Username string `json:"username"`
	Password string `json:"password"` // plaintext; hashed with argon2id
	Role     string `json:"role"`
}

func mgmtCreateUser(body []byte) ([]byte, error) {
	var in createUserBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.Username == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "username required"})
	}
	if in.Role == "" {
		in.Role = "user"
	}
	// Password hashing deferred to portal (argon2id). For admin-created accounts
	// we store a placeholder; the user sets a real password on first login or via
	// set-password. Empty password_hash means password login is disabled.
	hash := ""
	if in.Password != "" {
		// Simple sha256 for v0.1 admin-created accounts. Portal will re-hash with argon2id.
		// TODO: replace with argon2id once portal lands.
		hash = crypto.HashKey(in.Password)
	}
	u, errCreate := app.db.Users().Create(in.Username, hash, "", in.Role)
	if errCreate != nil {
		if errCreate == store.ErrDuplicate {
			return mgmtJSON(http.StatusConflict, map[string]string{"error": "username taken"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errCreate.Error()})
	}
	return mgmtJSON(http.StatusCreated, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role,
		"referral_code": u.ReferralCode, "balance": u.Balance,
	})
}

type rechargeBody struct {
	Amount  int64  `json:"amount"`  // micro-credit, signed
	Reason  string `json:"reason"`  // default recharge
	Channel string `json:"channel"` // dashboard|telegram|system
	RefID   string `json:"ref_id"`
}

func mgmtRecharge(userID string, body []byte) ([]byte, error) {
	var in rechargeBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.Amount == 0 {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "amount required"})
	}
	if in.Reason == "" {
		in.Reason = store.ReasonRecharge
	}
	if in.Channel == "" {
		in.Channel = "dashboard"
	}
	after, errAdj := app.db.Users().AdjustBalance(userID, in.Amount, in.Reason, in.RefID, in.Channel, "")
	if errAdj != nil {
		if errAdj == store.ErrNotFound {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		if errAdj == store.ErrInsufficientBalance {
			return mgmtJSON(http.StatusPaymentRequired, map[string]string{"error": "insufficient balance"})
		}
		if errAdj == store.ErrDuplicate {
			return mgmtJSON(http.StatusConflict, map[string]string{"error": "duplicate ref_id"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errAdj.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"user_id": userID, "delta": in.Amount, "balance_after": after,
	})
}

func mgmtListUsage() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, key_id, user_id, COALESCE(provider,''), COALESCE(model,''),
			COALESCE(requested_name,''), COALESCE(upstream_account,''),
			input_tokens, output_tokens, cost, COALESCE(source,''), billed, status, created_at
		FROM usage_records ORDER BY created_at DESC LIMIT 200`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID              int64  `json:"id"`
		KeyID           string `json:"key_id"`
		UserID          string `json:"user_id"`
		Provider        string `json:"provider"`
		Model           string `json:"model"`
		RequestedName   string `json:"requested_name"`
		UpstreamAccount string `json:"upstream_account"`
		InputTokens     int64  `json:"input_tokens"`
		OutputTokens    int64  `json:"output_tokens"`
		Cost            int64  `json:"cost"`
		Source          string `json:"source"`
		Billed          int    `json:"billed"`
		Status          string `json:"status"`
		CreatedAt       int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.KeyID, &r.UserID, &r.Provider, &r.Model,
			&r.RequestedName, &r.UpstreamAccount, &r.InputTokens, &r.OutputTokens,
			&r.Cost, &r.Source, &r.Billed, &r.Status, &r.CreatedAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"usage": out})
}

func mgmtStats() ([]byte, error) {
	var totalCost, totalRequests, activeKeys, totalUsers int64
	_ = app.db.SQL().QueryRow(`SELECT COALESCE(SUM(cost),0), COUNT(1) FROM usage_records WHERE billed = 1`).Scan(&totalCost, &totalRequests)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM keys WHERE status = 'active'`).Scan(&activeKeys)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM users`).Scan(&totalUsers)
	return mgmtJSON(http.StatusOK, map[string]any{
		"total_cost_micro": totalCost,
		"total_requests":   totalRequests,
		"active_keys":      activeKeys,
		"total_users":      totalUsers,
	})
}
