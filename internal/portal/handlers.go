package portal

import (
	"encoding/json"
	"net/http"
)

// --- Authenticated handlers ---

func (s *Server) handleMyKeys(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.getSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	keys, err := s.db.Keys().ListByUser(sess.UserID, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	type keyView struct {
		ID               string `json:"id"`
		Prefix           string `json:"prefix"`
		Name             string `json:"name"`
		Status           string `json:"status"`
		QuotaKind        string `json:"quota_kind"`
		QuotaScope       string `json:"quota_scope"`
		QuotaAmount      int64  `json:"quota_amount"`
		QuotaUsed        int64  `json:"quota_used"`
		ExpiresAt        int64  `json:"expires_at"`
		OverflowToWallet bool   `json:"overflow_to_wallet"`
		RPM              int    `json:"rpm"`
		CreatedAt        int64  `json:"created_at"`
		LastUsedAt       int64  `json:"last_used_at"`
	}
	out := make([]keyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyView{
			ID: k.ID, Prefix: k.Prefix, Name: k.Name, Status: k.Status,
			QuotaKind: k.QuotaKind, QuotaScope: k.QuotaScope,
			QuotaAmount: k.QuotaAmount, QuotaUsed: k.QuotaUsed,
			ExpiresAt: k.ExpiresAt, OverflowToWallet: k.OverflowToWallet,
			RPM: k.RPM, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) handleMyWallet(w http.ResponseWriter, r *http.Request) {
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
	// Fetch recent ledger entries.
	rows, errQuery := s.db.SQL().Query(`
		SELECT id, delta, reason, COALESCE(channel,''), balance_after, created_at
		FROM credit_ledger WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`, sess.UserID)
	if errQuery != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errQuery.Error()})
		return
	}
	defer rows.Close()
	type entry struct {
		ID           int64  `json:"id"`
		Delta        int64  `json:"delta"`
		Reason       string `json:"reason"`
		Channel      string `json:"channel"`
		BalanceAfter int64  `json:"balance_after"`
		CreatedAt    int64  `json:"created_at"`
	}
	var ledger []entry
	for rows.Next() {
		var e entry
		if errScan := rows.Scan(&e.ID, &e.Delta, &e.Reason, &e.Channel, &e.BalanceAfter, &e.CreatedAt); errScan != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": errScan.Error()})
			return
		}
		ledger = append(ledger, e)
	}
	if ledger == nil {
		ledger = []entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"balance":      u.Balance,
		"wallet_mode":  u.WalletMode,
		"credit_limit": u.CreditLimit,
		"ledger":       ledger,
	})
}

func (s *Server) handleMyReferrals(w http.ResponseWriter, r *http.Request) {
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
	// Count downline.
	var downlineCount int
	_ = s.db.SQL().QueryRow(`SELECT COUNT(1) FROM users WHERE referred_by = ?`, sess.UserID).Scan(&downlineCount)
	// Total earnings.
	var totalEarned int64
	_ = s.db.SQL().QueryRow(`SELECT COALESCE(SUM(reward),0) FROM referral_earnings WHERE user_id = ?`, sess.UserID).Scan(&totalEarned)

	link := s.cfg.BaseURL + "/?ref=" + u.ReferralCode
	writeJSON(w, http.StatusOK, map[string]any{
		"referral_code":  u.ReferralCode,
		"referral_link":  link,
		"downline_count": downlineCount,
		"total_earned":   totalEarned,
	})
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func readJSON(r *http.Request, dest any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(dest)
}
