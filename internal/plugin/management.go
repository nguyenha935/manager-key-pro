package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/billing"
	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/issue"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// managementRegister returns the routes CPA should expose under
// /v0/management/plugins/manager-key-pro/.
//
// NOTE: CPA's normalizeManagementRoute REJECTS any path containing ":" or "*",
// so :id path params are impossible. IDs are passed via query or body instead.
// All routes are prefixed /plugins/manager-key-pro so the host normalizes them
// to /v0/management/plugins/manager-key-pro/<path>.
func managementRegister() ([]byte, error) {
	p := func(path string) string { return "/plugins/manager-key-pro" + path }
	route := func(method, path string) map[string]string {
		return map[string]string{"Method": method, "Path": p(path)}
	}
	reg := map[string]any{
		"routes": []map[string]string{
			// Keys
			route("GET", "/keys"), route("POST", "/keys"), route("DELETE", "/keys"),
			route("GET", "/keys/detail"), route("POST", "/keys/reveal"),
			route("POST", "/keys/renew"), route("POST", "/keys/quota"),
			// Users
			route("GET", "/users"), route("POST", "/users"), route("GET", "/users/detail"),
			route("POST", "/users/recharge"), route("GET", "/users/ledger"),
			route("POST", "/users/status"),
			// Packages & orders
			route("GET", "/packages"), route("POST", "/packages"),
			route("POST", "/packages/update"), route("POST", "/packages/delete"),
			route("GET", "/orders"),
			// Data
			route("GET", "/usage"), route("GET", "/stats"),
			// Pricing & FX
			route("GET", "/pricing"), route("POST", "/pricing"),
			route("GET", "/fx"), route("POST", "/fx"),
			// Referral
			route("GET", "/referral/config"), route("POST", "/referral/config"),
			route("GET", "/referral/report"),
			// Logs & audit
			route("GET", "/logs"), route("POST", "/logs/config"),
			route("GET", "/audit"),
			// Backup / restore / settings
			route("GET", "/backup"), route("POST", "/restore"),
			route("GET", "/settings"),
		},
		// Single UI resource -> one sidebar menu item, not a menu per route.
		"resources": []map[string]string{
			{"Path": "/index.html", "Menu": "Manager Key Pro", "Description": "Admin dashboard"},
		},
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
	// Serve the embedded admin UI (resource route /index.html).
	if ui, errUI := serveAdminUI(req.Path); errUI == nil && ui != nil {
		resp := managementResponse{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html; charset=utf-8"}, "Cache-Control": {"no-store"}},
			Body:       ui,
		}
		out, errOut := json.Marshal(resp)
		if errOut != nil {
			return nil, fmt.Errorf("marshal ui: %w", errOut)
		}
		return okEnvelopeJSON(string(out))
	}
	// Strip the plugin prefix CPA may include.
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
	// ---- Keys ----
	case method == "GET" && path == "/keys":
		return mgmtListKeys()
	case method == "POST" && path == "/keys":
		return mgmtCreateKey(req.Body)
	case method == "GET" && path == "/keys/detail":
		return mgmtGetKey(queryVal(req, "id"))
	case method == "DELETE" && path == "/keys":
		return mgmtDeleteKey(queryVal(req, "id"))
	case method == "POST" && path == "/keys/reveal":
		return mgmtRevealKey(bodyStr(req, "id"))
	case method == "POST" && path == "/keys/renew":
		return mgmtRenewKey(bodyStr(req, "id"), req.Body)
	case method == "POST" && path == "/keys/quota":
		return mgmtSwitchQuota(bodyStr(req, "id"), req.Body)

	// ---- Users ----
	case method == "GET" && path == "/users":
		return mgmtListUsers()
	case method == "POST" && path == "/users":
		return mgmtCreateUser(req.Body)
	case method == "GET" && path == "/users/detail":
		return mgmtGetUser(queryVal(req, "id"))
	case method == "POST" && path == "/users/recharge":
		return mgmtRecharge(bodyStr(req, "user_id"), req.Body)
	case method == "GET" && path == "/users/ledger":
		return mgmtUserLedger(queryVal(req, "id"))
	case method == "POST" && path == "/users/status":
		return mgmtSetUserStatus(bodyStr(req, "id"), bodyStr(req, "status"))

	// ---- Packages & orders ----
	case method == "GET" && path == "/packages":
		return mgmtListPackages()
	case method == "POST" && path == "/packages":
		return mgmtCreatePackage(req.Body)
	case method == "POST" && path == "/packages/update":
		return mgmtUpdatePackage(req.Body)
	case method == "POST" && path == "/packages/delete":
		return mgmtDeletePackage(bodyStr(req, "id"))
	case method == "GET" && path == "/orders":
		return mgmtListOrders()

	// ---- Data ----
	case method == "GET" && path == "/usage":
		return mgmtListUsage()
	case method == "GET" && path == "/stats":
		return mgmtStats()

	// ---- Pricing & FX ----
	case method == "GET" && path == "/pricing":
		return mgmtListPricing()
	case method == "POST" && path == "/pricing":
		return mgmtPutPricing(req.Body)
	case method == "GET" && path == "/fx":
		return mgmtGetFX()
	case method == "POST" && path == "/fx":
		return mgmtPutFX(req.Body)

	// ---- Referral ----
	case method == "GET" && path == "/referral/config":
		return mgmtGetReferralConfig()
	case method == "POST" && path == "/referral/config":
		return mgmtPutReferralConfig(req.Body)
	case method == "GET" && path == "/referral/report":
		return mgmtReferralReport()

	// ---- Logs & audit ----
	case method == "GET" && path == "/logs":
		return mgmtListLogs(req)
	case method == "POST" && path == "/logs/config":
		return mgmtPutLogsConfig(req.Body)
	case method == "GET" && path == "/audit":
		return mgmtListAudit(req)

	// ---- Backup / restore / settings ----
	case method == "GET" && path == "/backup":
		return mgmtBackup()
	case method == "POST" && path == "/restore":
		return mgmtRestore(req.Body)
	case method == "GET" && path == "/settings":
		return mgmtGetSettings()

	default:
		return mgmtJSON(http.StatusNotFound, map[string]string{"error": "route not found", "path": path})
	}
}

// queryVal returns the first value for key in the request query string, or "".
// Used to pass record IDs without :id path params (rejected by CPA's normalizer).
func queryVal(req managementRequest, key string) string {
	if vals := req.Query[key]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// bodyStr decodes the request body as a JSON object and returns the field named
// by key as a string. Returns "" when missing.
func bodyStr(req managementRequest, key string) string {
	var obj map[string]any
	if err := json.Unmarshal(req.Body, &obj); err != nil {
		return ""
	}
	if v, ok := obj[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%.0f", val)
		case bool:
			if val {
				return "true"
			}
			return "false"
		}
	}
	return ""
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

// mgmtBinary returns a non-JSON response (used for the DB backup download).
func mgmtBinary(status int, contentType string, body []byte) ([]byte, error) {
	resp := managementResponse{
		StatusCode: status,
		Headers: map[string][]string{
			"Content-Type":        {contentType},
			"Content-Disposition": {"attachment; filename=manager-key-pro-backup.db"},
		},
		Body: body,
	}
	out, errOut := json.Marshal(resp)
	if errOut != nil {
		return nil, fmt.Errorf("marshal response: %w", errOut)
	}
	return okEnvelopeJSON(string(out))
}

// ---- Keys handlers ----

func mgmtListKeys() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, user_id, prefix, name, status, quota_kind, quota_scope,
			quota_amount, quota_used, expires_at, overflow_to_wallet, rpm,
			created_at, COALESCE(last_used_at,0)
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
		"rpm": k.RPM, "allowed_models": k.AllowedModels, "log_mode": k.LogMode,
		"created_at": k.CreatedAt, "last_used_at": k.LastUsedAt,
	})
}

type createKeyBody struct {
	UserID      string   `json:"user_id"`
	PackageID   string   `json:"package_id"`
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

	// When a package is supplied, apply its quota spec to the new key.
	if in.PackageID != "" {
		pkg, errPkg := app.db.Packages().ByID(in.PackageID)
		if errPkg != nil {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "package not found"})
		}
		in.QuotaKind = pkg.QuotaKind
		in.QuotaScope = pkg.QuotaScope
		in.QuotaAmount = pkg.QuotaAmount
		if pkg.DurationDays > 0 {
			in.ExpiresAt = store.Now() + pkg.DurationDays*24*60*60*1000
		} else {
			in.ExpiresAt = -1
		}
		in.RPM = pkg.RPM
		if len(pkg.ModelsJSON) > 2 {
			_ = json.Unmarshal([]byte(pkg.ModelsJSON), &in.Models)
		}
		if in.Name == "" {
			in.Name = pkg.Name
		}
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

	k, plain, errIssue := issue.Key(app.db, app.secretKey, in.UserID, issue.Spec{
		Name: in.Name, QuotaKind: in.QuotaKind, QuotaScope: in.QuotaScope,
		QuotaAmount: in.QuotaAmount, ExpiresAt: in.ExpiresAt, RPM: in.RPM,
		Models: in.Models, PackageID: in.PackageID,
	}, "admin")
	if errIssue != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errIssue.Error()})
	}
	if in.Overflow {
		if errOverflow := app.db.Keys().SetOverflow(k.ID, true); errOverflow != nil {
			log.Printf("[mkp] set overflow: %v", errOverflow)
		}
	}
	return mgmtJSON(http.StatusCreated, map[string]any{
		"id": k.ID, "user_id": k.UserID, "name": k.Name,
		"prefix": k.Prefix, "plain_key": plain,
		"quota_kind": k.QuotaKind, "quota_amount": k.QuotaAmount,
		"expires_at": k.ExpiresAt,
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
	audit("admin", "key.reveal", k.ID, k.UserID, "{}")
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
	audit("admin", "key.delete", id, "", "{}")
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
	quotaHistory(id, "renew",
		fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, k.QuotaAmount, k.ExpiresAt),
		fmt.Sprintf(`{"quota_amount":%d,"expires_at":%d}`, newAmount, newExpires), "admin")
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": id, "quota_amount": newAmount, "expires_at": newExpires,
	})
}

// mgmtSwitchQuota changes the quota type of a key (design §2.2 PATCH quota).
func mgmtSwitchQuota(id string, body []byte) ([]byte, error) {
	var in struct {
		QuotaKind   string `json:"quota_kind"`
		QuotaScope  string `json:"quota_scope"`
		QuotaAmount int64  `json:"quota_amount"`
		ExpiresAt   int64  `json:"expires_at"`
	}
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
	if in.QuotaKind == "" {
		in.QuotaKind = k.QuotaKind
	}
	if in.QuotaScope == "" {
		in.QuotaScope = k.QuotaScope
	}
	if in.QuotaAmount <= 0 {
		in.QuotaAmount = k.QuotaAmount
	}
	if in.ExpiresAt == 0 {
		in.ExpiresAt = k.ExpiresAt
	}
	if _, errExec := app.db.SQL().Exec(
		`UPDATE keys SET quota_kind = ?, quota_scope = ?, quota_amount = ?, quota_used = 0, expires_at = ?, updated_at = ? WHERE id = ?`,
		in.QuotaKind, in.QuotaScope, in.QuotaAmount, in.ExpiresAt, store.Now(), id); errExec != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errExec.Error()})
	}
	quotaHistory(id, "switch",
		fmt.Sprintf(`{"quota_kind":%q,"quota_scope":%q,"quota_amount":%d,"expires_at":%d}`, k.QuotaKind, k.QuotaScope, k.QuotaAmount, k.ExpiresAt),
		fmt.Sprintf(`{"quota_kind":%q,"quota_scope":%q,"quota_amount":%d,"expires_at":%d}`, in.QuotaKind, in.QuotaScope, in.QuotaAmount, in.ExpiresAt), "admin")
	audit("admin", "quota.switch", id, k.UserID, fmt.Sprintf(`{"to_kind":%q,"to_scope":%q}`, in.QuotaKind, in.QuotaScope))
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": id, "quota_kind": in.QuotaKind, "quota_scope": in.QuotaScope,
		"quota_amount": in.QuotaAmount, "expires_at": in.ExpiresAt,
	})
}

func quotaHistory(keyID, action, beforeJSON, afterJSON, actor string) {
	if _, errHist := app.db.SQL().Exec(
		`INSERT INTO key_quota_history (key_id, action, before_json, after_json, actor, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, keyID, action, beforeJSON, afterJSON, actor, store.Now()); errHist != nil {
		log.Printf("[mkp] quota history: %v", errHist)
	}
}

func audit(actor, action, keyID, userID, detail string) {
	if _, errAudit := app.db.SQL().Exec(
		`INSERT INTO audit_log (user_id, key_id, actor, action, detail, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		nullStr(userID), nullStr(keyID), actor, action, detail, store.Now()); errAudit != nil {
		log.Printf("[mkp] audit %s: %v", action, errAudit)
	}
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---- Users handlers ----

func mgmtListUsers() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, username, COALESCE(telegram_id,''), role, status, balance,
			wallet_mode, credit_limit, referral_code, created_at, COALESCE(last_login_at,0),
			COALESCE(referred_by,'')
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
		ReferredBy   string `json:"referred_by"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.Username, &r.TelegramID, &r.Role, &r.Status,
			&r.Balance, &r.WalletMode, &r.CreditLimit, &r.ReferralCode,
			&r.CreatedAt, &r.LastLoginAt, &r.ReferredBy); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"users": out})
}

func mgmtGetUser(id string) ([]byte, error) {
	u, errUser := app.db.Users().ByID(id)
	if errUser != nil {
		if store.IsNotFound(errUser) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errUser.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "telegram_id": u.TelegramID,
		"role": u.Role, "status": u.Status, "balance": u.Balance,
		"wallet_mode": u.WalletMode, "credit_limit": u.CreditLimit,
		"referral_code": u.ReferralCode, "referred_by": u.ReferredBy,
		"created_at": u.CreatedAt, "last_login_at": u.LastLoginAt,
	})
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
	hash := ""
	if in.Password != "" {
		// Simple sha256 for v0.1 admin-created accounts. Portal re-hashes with
		// argon2id on first password change. TODO: argon2id here as well.
		hash = crypto.HashKey(in.Password)
	}
	u, errCreate := app.db.Users().Create(in.Username, hash, "", in.Role)
	if errCreate != nil {
		if errCreate == store.ErrDuplicate {
			return mgmtJSON(http.StatusConflict, map[string]string{"error": "username taken"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errCreate.Error()})
	}
	audit("admin", "user.create", "", u.ID, fmt.Sprintf(`{"username":%q}`, u.Username))
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
	audit("admin", "wallet.recharge", "", userID, fmt.Sprintf(`{"amount":%d,"channel":%q}`, in.Amount, in.Channel))
	// Pay referral rewards when this is a real recharge.
	if in.Reason == store.ReasonRecharge && in.Amount > 0 {
		referralOnRecharge(userID, in.Amount, in.RefID)
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"user_id": userID, "delta": in.Amount, "balance_after": after,
	})
}

func mgmtUserLedger(id string) ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, delta, reason, COALESCE(channel,''), balance_after, created_at, COALESCE(key_id,'')
		FROM credit_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT 200`, id)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type entry struct {
		ID           int64  `json:"id"`
		Delta        int64  `json:"delta"`
		Reason       string `json:"reason"`
		Channel      string `json:"channel"`
		BalanceAfter int64  `json:"balance_after"`
		CreatedAt    int64  `json:"created_at"`
		KeyID        string `json:"key_id"`
	}
	var ledger []entry
	for rows.Next() {
		var e entry
		if errScan := rows.Scan(&e.ID, &e.Delta, &e.Reason, &e.Channel, &e.BalanceAfter, &e.CreatedAt, &e.KeyID); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		ledger = append(ledger, e)
	}
	if ledger == nil {
		ledger = []entry{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"user_id": id, "ledger": ledger})
}

func mgmtSetUserStatus(id, status string) ([]byte, error) {
	switch status {
	case "active", "pending", "disabled", "banned":
	default:
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid status"})
	}
	if errStatus := app.db.Users().SetStatus(id, status); errStatus != nil {
		if store.IsNotFound(errStatus) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errStatus.Error()})
	}
	audit("admin", "user.status", "", id, fmt.Sprintf(`{"status":%q}`, status))
	return mgmtJSON(http.StatusOK, map[string]string{"id": id, "status": status})
}

// ---- Packages & orders handlers ----

func mgmtListPackages() ([]byte, error) {
	pkgs, errList := app.db.Packages().List(true)
	if errList != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errList.Error()})
	}
	type view struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		QuotaKind    string   `json:"quota_kind"`
		QuotaScope   string   `json:"quota_scope"`
		QuotaAmount  int64    `json:"quota_amount"`
		DurationDays int64    `json:"duration_days"`
		PriceCredit  int64    `json:"price_credit"`
		Models       []string `json:"allowed_models"`
		RPM          int      `json:"rpm"`
		Visible      bool     `json:"visible"`
		CreatedAt    int64    `json:"created_at"`
	}
	var out []view
	for _, p := range pkgs {
		var models []string
		_ = json.Unmarshal([]byte(p.ModelsJSON), &models)
		out = append(out, view{p.ID, p.Name, p.Description, p.QuotaKind, p.QuotaScope,
			p.QuotaAmount, p.DurationDays, p.PriceCredit, models, p.RPM, p.Visible, p.CreatedAt})
	}
	if out == nil {
		out = []view{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"packages": out})
}

type packageBody struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	QuotaKind    string   `json:"quota_kind"`
	QuotaScope   string   `json:"quota_scope"`
	QuotaAmount  int64    `json:"quota_amount"`
	DurationDays int64    `json:"duration_days"`
	PriceCredit  int64    `json:"price_credit"`
	Models       []string `json:"allowed_models"`
	RPM          int      `json:"rpm"`
	Visible      *bool    `json:"visible"`
}

func (b packageBody) toInput() store.CreatePackageInput {
	visible := true
	if b.Visible != nil {
		visible = *b.Visible
	}
	return store.CreatePackageInput{
		Name: b.Name, Description: b.Description, QuotaKind: b.QuotaKind,
		QuotaScope: b.QuotaScope, QuotaAmount: b.QuotaAmount,
		DurationDays: b.DurationDays, PriceCredit: b.PriceCredit,
		Models: b.Models, RPM: b.RPM, Visible: visible,
	}
}

func mgmtCreatePackage(body []byte) ([]byte, error) {
	var in packageBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	pkg, errCreate := app.db.Packages().Create(in.toInput())
	if errCreate != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": errCreate.Error()})
	}
	audit("admin", "package.create", "", "", fmt.Sprintf(`{"name":%q,"price_credit":%d}`, pkg.Name, pkg.PriceCredit))
	return mgmtJSON(http.StatusCreated, map[string]any{"id": pkg.ID, "name": pkg.Name})
}

func mgmtUpdatePackage(body []byte) ([]byte, error) {
	var in packageBody
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.ID == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "id required"})
	}
	pkg, errUpdate := app.db.Packages().Update(in.ID, in.toInput())
	if errUpdate != nil {
		if store.IsNotFound(errUpdate) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "package not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errUpdate.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{"id": pkg.ID, "name": pkg.Name})
}

func mgmtDeletePackage(id string) ([]byte, error) {
	if errDel := app.db.Packages().Delete(id); errDel != nil {
		if store.IsNotFound(errDel) {
			return mgmtJSON(http.StatusNotFound, map[string]string{"error": "package not found"})
		}
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errDel.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

func mgmtListOrders() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT o.id, o.user_id, COALESCE(u.username,''), o.package_id, COALESCE(p.name,''),
			COALESCE(o.key_id,''), o.kind, o.price_credit, o.status, o.created_at
		FROM orders o
		LEFT JOIN users u ON u.id = o.user_id
		LEFT JOIN packages p ON p.id = o.package_id
		ORDER BY o.created_at DESC LIMIT 200`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID          string `json:"id"`
		UserID      string `json:"user_id"`
		Username    string `json:"username"`
		PackageID   string `json:"package_id"`
		PackageName string `json:"package_name"`
		KeyID       string `json:"key_id"`
		Kind        string `json:"kind"`
		PriceCredit int64  `json:"price_credit"`
		Status      string `json:"status"`
		CreatedAt   int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.UserID, &r.Username, &r.PackageID, &r.PackageName,
			&r.KeyID, &r.Kind, &r.PriceCredit, &r.Status, &r.CreatedAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"orders": out})
}

// ---- Data handlers ----

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
	var totalCost, totalRequests, activeKeys, totalUsers, revenue, orderCount, pendingUsers int64
	_ = app.db.SQL().QueryRow(`SELECT COALESCE(SUM(cost),0), COUNT(1) FROM usage_records WHERE billed = 1`).Scan(&totalCost, &totalRequests)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM keys WHERE status = 'active'`).Scan(&activeKeys)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM users`).Scan(&totalUsers)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM users WHERE status = 'pending'`).Scan(&pendingUsers)
	_ = app.db.SQL().QueryRow(`SELECT COALESCE(SUM(delta),0) FROM credit_ledger WHERE reason = 'recharge' AND delta > 0`).Scan(&revenue)
	_ = app.db.SQL().QueryRow(`SELECT COUNT(1) FROM orders WHERE status = 'paid'`).Scan(&orderCount)
	return mgmtJSON(http.StatusOK, map[string]any{
		"total_cost_micro": totalCost,
		"total_requests":   totalRequests,
		"active_keys":      activeKeys,
		"total_users":      totalUsers,
		"pending_users":    pendingUsers,
		"revenue_micro":    revenue,
		"paid_orders":      orderCount,
	})
}

// ---- Pricing & FX handlers ----

func mgmtListPricing() ([]byte, error) {
	prices, errList := billing.ListPrices(app.db)
	if errList != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errList.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{"pricing": prices})
}

func mgmtPutPricing(body []byte) ([]byte, error) {
	var in billing.Price
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.Model == "" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "model required"})
	}
	if errUpdate := billing.UpdatePrice(app.db, in); errUpdate != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errUpdate.Error()})
	}
	audit("admin", "pricing.update", "", "", fmt.Sprintf(`{"model":%q}`, in.Model))
	return mgmtJSON(http.StatusOK, map[string]any{"model": in.Model, "status": "updated"})
}

func mgmtGetFX() ([]byte, error) {
	return mgmtJSON(http.StatusOK, map[string]any{
		"fx_mode":     app.db.Settings().Get(store.SettingFXMode),
		"vnd_per_usd": app.db.Settings().Get(store.SettingVNDPerUSD),
	})
}

func mgmtPutFX(body []byte) ([]byte, error) {
	var in struct {
		Mode      string `json:"fx_mode"`
		VNDPerUSD string `json:"vnd_per_usd"`
	}
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.Mode != "" {
		if in.Mode != "manual" && in.Mode != "auto" {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "fx_mode must be manual or auto"})
		}
		if errSet := app.db.Settings().Set(store.SettingFXMode, in.Mode); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.VNDPerUSD != "" {
		if errSet := app.db.Settings().Set(store.SettingVNDPerUSD, in.VNDPerUSD); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	return mgmtGetFX()
}

// ---- Referral handlers ----

func mgmtGetReferralConfig() ([]byte, error) {
	var tiers []int64
	app.db.Settings().GetJSON(store.SettingReferralTiers, &tiers)
	return mgmtJSON(http.StatusOK, map[string]any{
		"mode":         app.db.Settings().Get(store.SettingReferralMode),
		"tiers":        tiers,
		"fixed_credit": app.db.Settings().GetInt(store.SettingReferralFixed, 0),
		"qualify":      app.db.Settings().GetInt(store.SettingReferralQualify, 0),
	})
}

func mgmtPutReferralConfig(body []byte) ([]byte, error) {
	var in struct {
		Mode    string  `json:"mode"`
		Tiers   []int64 `json:"tiers"`
		Fixed   int64   `json:"fixed_credit"`
		Qualify int64   `json:"qualify_recharge"`
	}
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.Mode != "" {
		if in.Mode != "percent" && in.Mode != "fixed" {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "mode must be percent or fixed"})
		}
		if errSet := app.db.Settings().Set(store.SettingReferralMode, in.Mode); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if len(in.Tiers) > 0 {
		if errSet := app.db.Settings().SetJSON(store.SettingReferralTiers, in.Tiers); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.Fixed > 0 {
		if errSet := app.db.Settings().SetInt(store.SettingReferralFixed, in.Fixed); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	if in.Qualify > 0 {
		if errSet := app.db.Settings().SetInt(store.SettingReferralQualify, in.Qualify); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	return mgmtGetReferralConfig()
}

func mgmtReferralReport() ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT e.user_id, COALESCE(u.username,''), COUNT(1), COALESCE(SUM(e.reward),0), MAX(e.tier)
		FROM referral_earnings e LEFT JOIN users u ON u.id = e.user_id
		GROUP BY e.user_id ORDER BY SUM(e.reward) DESC LIMIT 200`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		Count    int64  `json:"earning_count"`
		Total    int64  `json:"total_reward_micro"`
		MaxTier  int    `json:"max_tier"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.UserID, &r.Username, &r.Count, &r.Total, &r.MaxTier); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"report": out})
}

// ---- Logs & audit handlers ----

func mgmtListLogs(req managementRequest) ([]byte, error) {
	keyID := queryVal(req, "key_id")
	mode := queryVal(req, "mode")
	q := `SELECT id, COALESCE(key_id,''), COALESCE(user_id,''), mode,
		COALESCE(error_code,''), COALESCE(upstream_status,0), COALESCE(provider,''),
		COALESCE(attempt,0), COALESCE(purge_after,0), created_at
		FROM request_logs`
	var conds []string
	var args []any
	if keyID != "" {
		conds = append(conds, "key_id = ?")
		args = append(args, keyID)
	}
	if mode != "" {
		conds = append(conds, "mode = ?")
		args = append(args, mode)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT 200"
	rows, errQuery := app.db.SQL().Query(q, args...)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID             int64  `json:"id"`
		KeyID          string `json:"key_id"`
		UserID         string `json:"user_id"`
		Mode           string `json:"mode"`
		ErrorCode      string `json:"error_code"`
		UpstreamStatus int    `json:"upstream_status"`
		Provider       string `json:"provider"`
		Attempt        int    `json:"attempt"`
		PurgeAfter     int64  `json:"purge_after"`
		CreatedAt      int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.KeyID, &r.UserID, &r.Mode, &r.ErrorCode,
			&r.UpstreamStatus, &r.Provider, &r.Attempt, &r.PurgeAfter, &r.CreatedAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"logs": out, "global_mode": app.db.Settings().Get(store.SettingGlobalLogMode)})
}

func mgmtPutLogsConfig(body []byte) ([]byte, error) {
	var in struct {
		Mode             string `json:"mode"` // global mode
		FullRetentionHrs int64  `json:"full_retention_hours"`
		KeyID            string `json:"key_id"`   // optional per-key override
		KeyMode          string `json:"key_mode"` // full|standard|error_only|""(inherit)
	}
	if errUnmarshal := json.Unmarshal(body, &in); errUnmarshal != nil {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if in.KeyID != "" {
		if errSet := app.db.Keys().SetLogMode(in.KeyID, in.KeyMode); errSet != nil {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": errSet.Error()})
		}
		audit("admin", "log.mode", in.KeyID, "", fmt.Sprintf(`{"key_mode":%q}`, in.KeyMode))
	}
	if in.Mode != "" {
		if in.Mode != "full" && in.Mode != "standard" && in.Mode != "error_only" {
			return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "invalid mode"})
		}
		if errSet := app.db.Settings().Set(store.SettingGlobalLogMode, in.Mode); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
		if in.Mode == "full" {
			audit("admin", "log.mode.global", "", "", `{"mode":"full"}`)
		}
	}
	if in.FullRetentionHrs > 0 {
		if errSet := app.db.Settings().SetInt(store.SettingFullRetentionHours, in.FullRetentionHrs); errSet != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errSet.Error()})
		}
	}
	return mgmtJSON(http.StatusOK, map[string]any{
		"global_mode":          app.db.Settings().Get(store.SettingGlobalLogMode),
		"full_retention_hours": app.db.Settings().GetInt(store.SettingFullRetentionHours, 24),
	})
}

func mgmtListAudit(req managementRequest) ([]byte, error) {
	rows, errQuery := app.db.SQL().Query(`
		SELECT id, COALESCE(user_id,''), COALESCE(key_id,''), actor, action, detail, created_at
		FROM audit_log ORDER BY created_at DESC LIMIT 200`)
	if errQuery != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
	}
	defer rows.Close()
	type row struct {
		ID        int64  `json:"id"`
		UserID    string `json:"user_id"`
		KeyID     string `json:"key_id"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Detail    string `json:"detail"`
		CreatedAt int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if errScan := rows.Scan(&r.ID, &r.UserID, &r.KeyID, &r.Actor, &r.Action, &r.Detail, &r.CreatedAt); errScan != nil {
			return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	return mgmtJSON(http.StatusOK, map[string]any{"audit": out})
}

// ---- Backup / restore / settings handlers ----

func mgmtBackup() ([]byte, error) {
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("mkp-backup-%d.db", store.Now()))
	if _, errExec := app.db.SQL().Exec(`VACUUM INTO ?`, tmp); errExec != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": "vacuum into: " + errExec.Error()})
	}
	defer os.Remove(tmp)
	data, errRead := os.ReadFile(tmp)
	if errRead != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": "read backup: " + errRead.Error()})
	}
	return mgmtBinary(http.StatusOK, "application/x-sqlite3", data)
}

func mgmtRestore(body []byte) ([]byte, error) {
	if len(body) < 16 || string(body[0:15]) != "SQLite format 3" {
		return mgmtJSON(http.StatusBadRequest, map[string]string{"error": "body is not a SQLite database"})
	}
	if errRestore := app.RestoreDB(body); errRestore != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errRestore.Error()})
	}
	audit("admin", "db.restore", "", "", fmt.Sprintf(`{"size":%d}`, len(body)))
	return mgmtJSON(http.StatusOK, map[string]string{"status": "restored"})
}

func mgmtGetSettings() ([]byte, error) {
	all, errAll := app.db.Settings().All()
	if errAll != nil {
		return mgmtJSON(http.StatusInternalServerError, map[string]string{"error": errAll.Error()})
	}
	return mgmtJSON(http.StatusOK, map[string]any{"settings": all})
}

// referralOnRecharge is a thin wrapper so management.go does not import the
// referral package directly (keeps import graph simple). Implemented in app.go.
func referralOnRecharge(userID string, amount int64, refID string) {
	if app != nil && app.onRecharge != nil {
		app.onRecharge(userID, amount, refID)
	}
}
