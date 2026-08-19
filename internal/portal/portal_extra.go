package portal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/issue"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// --- Telegram login ---

func (s *Server) handleTelegramLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.TelegramBotToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "telegram not configured"})
		return
	}
	var in map[string]string
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := verifyTelegramLogin(in, s.cfg.TelegramBotToken); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	telegramID := in["id"]
	username := in["username"]
	if username == "" {
		username = "tg_" + telegramID
	}
	// Existing user?
	u, errUser := s.db.Users().ByTelegramID(telegramID)
	if errUser != nil {
		if !store.IsNotFound(errUser) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errUser.Error()})
			return
		}
		// Create. Mark telegram_id; password empty.
		u, errUser = s.db.Users().Create(username, "", telegramID, "user")
		if errUser != nil {
			if errUser == store.ErrDuplicate {
				// username taken: suffix telegram id
				u, errUser = s.db.Users().Create(username+"_"+telegramID, "", telegramID, "user")
				if errUser != nil {
					writeJSON(w, http.StatusConflict, map[string]string{"error": errUser.Error()})
					return
				}
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errUser.Error()})
				return
			}
		}
		// Attach referral if cookie set.
		if ref := s.readRefCookie(r); ref != "" {
			_ = s.attachReferral(u.ID, ref)
		}
	}
	if u.Status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account not active", "status": u.Status})
		return
	}
	s.db.Users().RecordLogin(u.ID)
	token := s.createSession(u.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role,
		"referral_code": u.ReferralCode, "session_token": token,
	})
}

// verifyTelegramLogin validates a Telegram Login Widget payload using the
// standard HMAC-SHA256 check with bot_token as the secret key.
func verifyTelegramLogin(params map[string]string, botToken string) error {
	hash := params["hash"]
	if hash == "" {
		return fmt.Errorf("hash missing")
	}
	// auth_date must be within 24h.
	ad := params["auth_date"]
	if ad == "" {
		return fmt.Errorf("auth_date missing")
	}
	var ts int64
	if _, err := fmt.Sscanf(ad, "%d", &ts); err != nil {
		return fmt.Errorf("invalid auth_date")
	}
	if time.Now().Unix()-ts > 24*3600 {
		return fmt.Errorf("auth_date too old")
	}
	// Build data_check_string.
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "hash" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(params[k])
	}
	// secret_key = sha256(bot_token), data_check_string hashed with HMAC-SHA256.
	secret := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(b.String()))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !strings.EqualFold(hash, expected) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}

func (s *Server) handleLinkTelegram(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	if s.cfg.TelegramBotToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "telegram not configured"})
		return
	}
	var in map[string]string
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := verifyTelegramLogin(in, s.cfg.TelegramBotToken); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	if err := s.db.Users().LinkTelegram(sess.UserID, in["id"]); err != nil {
		if err == store.ErrDuplicate {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "telegram already linked"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "linked"})
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil || len(in.Password) < s.cfg.MinPasswordLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password too short"})
		return
	}
	hash := hashPassword(in.Password)
	if err := s.db.Users().SetPassword(sess.UserID, hash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// --- Account info ---

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	u, err := s.db.Users().ByID(sess.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role,
		"status": u.Status, "balance": u.Balance, "wallet_mode": u.WalletMode,
		"telegram_id": u.TelegramID, "referral_code": u.ReferralCode,
		"created_at": u.CreatedAt, "last_login_at": u.LastLoginAt,
	})
}

// --- Key reveal / update ---

func (s *Server) handleMyKeyReveal(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &in); err != nil || in.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	k, err := s.db.Keys().ByID(in.ID)
	if err != nil || k.UserID != sess.UserID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	plain, err := crypto.DecryptKey(k.KeyCipher, k.KeyNonce, s.cfg.SecretKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "decrypt failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": k.ID, "plain_key": plain, "prefix": k.Prefix})
}

func (s *Server) handleMyKeyUpdate(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	var in struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Overflow *bool  `json:"overflow_to_wallet"`
	}
	if err := readJSON(r, &in); err != nil || in.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	k, err := s.db.Keys().ByID(in.ID)
	if err != nil || k.UserID != sess.UserID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	if in.Name != "" {
		_ = s.db.Keys().Rename(in.ID, in.Name)
	}
	if in.Overflow != nil {
		_ = s.db.Keys().SetOverflow(in.ID, *in.Overflow)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// --- Usage history ---

func (s *Server) handleMyUsage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	rows, err := s.db.SQL().Query(`
		SELECT COALESCE(provider,''), COALESCE(model,''), COALESCE(requested_name,''),
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			cost, COALESCE(source,''), billed, status, created_at
		FROM usage_records WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`, sess.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		Provider            string `json:"provider"`
		Model               string `json:"model"`
		Alias               string `json:"alias"`
		InputTokens         int64  `json:"input_tokens"`
		OutputTokens        int64  `json:"output_tokens"`
		CacheReadTokens     int64  `json:"cache_read_tokens"`
		CacheCreationTokens int64  `json:"cache_creation_tokens"`
		Cost                int64  `json:"cost"`
		Source              string `json:"source"`
		Billed              int    `json:"billed"`
		Status              string `json:"status"`
		CreatedAt           int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Provider, &r.Model, &r.Alias, &r.InputTokens, &r.OutputTokens,
			&r.CacheReadTokens, &r.CacheCreationTokens,
			&r.Cost, &r.Source, &r.Billed, &r.Status, &r.CreatedAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": out})
}

// --- Packages & orders ---

func (s *Server) handlePublicPackages(w http.ResponseWriter, r *http.Request) {
	pkgs, err := s.db.Packages().List(false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type view struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		QuotaKind    string   `json:"quota_kind"`
		QuotaScope   string   `json:"quota_scope"`
		QuotaAmount  int64    `json:"quota_amount"`
		PlanType     string   `json:"plan_type"`
		WindowHours  int64    `json:"window_hours"`
		DurationDays int64    `json:"duration_days"`
		PriceCredit  int64    `json:"price_credit"`
		Models       []string `json:"allowed_models"`
	}
	out := []view{}
	for _, p := range pkgs {
		var models []string
		_ = json.Unmarshal([]byte(p.ModelsJSON), &models)
		out = append(out, view{p.ID, p.Name, p.Description, p.QuotaKind, p.QuotaScope,
			p.QuotaAmount, p.PlanType, p.WindowHours, p.DurationDays, p.PriceCredit, models})
	}
	writeJSON(w, http.StatusOK, map[string]any{"packages": out})
}

func (s *Server) handleBuyPackage(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	var in struct {
		PackageID  string `json:"package_id"`
		Kind       string `json:"kind"`   // new_key | renew
		RenewKeyID string `json:"key_id"` // for renew
	}
	if err := readJSON(r, &in); err != nil || in.PackageID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "package_id required"})
		return
	}
	if in.Kind == "" {
		in.Kind = "new_key"
	}
	ordID, keyID, plain, err := issue.BuyPackage(s.db, s.cfg.SecretKey, sess.UserID, in.PackageID, in.Kind, in.RenewKeyID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"order_id": ordID, "key_id": keyID, "plain_key": plain,
	})
}

func (s *Server) handleMyOrders(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	rows, err := s.db.SQL().Query(`
		SELECT id, package_id, COALESCE(key_id,''), kind, price_credit, status, created_at
		FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`, sess.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	type row struct {
		ID          string `json:"id"`
		PackageID   string `json:"package_id"`
		KeyID       string `json:"key_id"`
		Kind        string `json:"kind"`
		PriceCredit int64  `json:"price_credit"`
		Status      string `json:"status"`
		CreatedAt   int64  `json:"created_at"`
	}
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.PackageID, &r.KeyID, &r.Kind, &r.PriceCredit, &r.Status, &r.CreatedAt); err != nil {
			continue
		}
		out = append(out, r)
	}
	if out == nil {
		out = []row{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": out})
}

// --- Telegram store webhook (nạp ví) ---

func (s *Server) handleWebhookRecharge(w http.ResponseWriter, r *http.Request) {
	if s.cfg.TelegramBotToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "telegram not configured"})
		return
	}
	// Validate shared secret header (admin configures the same secret on the bot).
	secret := r.Header.Get("X-Webhook-Secret")
	if secret == "" || secret != s.cfg.WebhookSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid secret"})
		return
	}
	var in struct {
		UserID string `json:"user_id"`
		Amount int64  `json:"amount"`
		TxID   string `json:"tx_id"`
	}
	if err := readJSON(r, &in); err != nil || in.UserID == "" || in.Amount <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if _, err := s.db.Users().AdjustBalance(in.UserID, in.Amount, store.ReasonRecharge, in.TxID, "telegram", ""); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "user_id": in.UserID})
}

// --- Referral helpers ---

func (s *Server) readRefCookie(r *http.Request) string {
	if c, err := r.Cookie("mkp_ref"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("ref")
}

func (s *Server) attachReferral(userID, refCode string) error {
	var referrerID string
	err := s.db.SQL().QueryRow(`SELECT id FROM users WHERE referral_code = ?`, refCode).Scan(&referrerID)
	if err != nil || referrerID == "" {
		return fmt.Errorf("referral code not found")
	}
	if referrerID == userID {
		return fmt.Errorf("cannot refer self")
	}
	_, err = s.db.SQL().Exec(`UPDATE users SET referred_by = ? WHERE id = ? AND referred_by IS NULL`, referrerID, userID)
	return err
}

// SetWebhookSecret stores a secret used to authenticate the recharge webhook.
// Called by Start() after the server is constructed.
func (s *Server) setWebhookSecret(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.WebhookSecret = secret
}

// cfgJSON is a small helper so the plugin can pass a secret at New().
type cfgJSON struct {
	WebhookSecret string
}

var _ = log.Printf

// handleIndex serves the embedded user portal SPA.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(portalUIHTML))
}

// handleKeyCheck is the public key-check endpoint (design §7): no session required.
// Accepts Authorization Bearer / X-Api-Key / ?key= and returns status + remaining.
func (s *Server) handleKeyCheck(w http.ResponseWriter, r *http.Request) {
	plaintext := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		plaintext = strings.TrimSpace(auth[7:])
	}
	if plaintext == "" {
		plaintext = r.Header.Get("X-Api-Key")
	}
	if plaintext == "" {
		plaintext = r.URL.Query().Get("key")
	}
	if plaintext == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing key"})
		return
	}
	k, errKey := s.db.Keys().ByHash(crypto.HashKey(plaintext))
	if errKey != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_api_key"})
		return
	}
	remaining := k.QuotaAmount - k.QuotaUsed
	if remaining < 0 {
		remaining = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": k.Status, "prefix": k.Prefix, "name": k.Name,
		"quota_kind": k.QuotaKind, "quota_scope": k.QuotaScope,
		"quota_amount": k.QuotaAmount, "quota_used": k.QuotaUsed, "quota_remaining": remaining,
		"plan_type": k.PlanType, "window_hours": k.WindowHours,
		"period_end": k.PeriodEnd, "expires_at": k.ExpiresAt,
		"overflow_to_wallet": k.OverflowToWallet, "rpm": k.RPM,
	})
}
