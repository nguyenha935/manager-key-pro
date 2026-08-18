// Package referral implements the two admin-selectable reward modes (design §4b):
// percent — % per tier on downline recharges; fixed — one-time credit per
// qualified invite. Rewards are only ever paid on REAL money recharged.
package referral

import (
	"database/sql"
	"log"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// OnRecharge pays referral rewards after a successful wallet recharge.
func OnRecharge(db *store.DB, userID string, amount int64, refID string) {
	if amount <= 0 {
		return
	}
	u, errUser := db.Users().ByID(userID)
	if errUser != nil || u.ReferredBy == "" {
		return
	}
	switch db.Settings().Get(store.SettingReferralMode) {
	case "percent":
		payPercent(db, u, amount, refID)
	case "fixed":
		payFixed(db, u, refID)
	}
}

// payPercent walks the upline chain paying tiers[i]% of the recharge amount.
func payPercent(db *store.DB, u store.User, amount int64, refID string) {
	var tiers []int64
	if !db.Settings().GetJSON(store.SettingReferralTiers, &tiers) || len(tiers) == 0 {
		return
	}
	upline := u.ReferredBy
	seen := map[string]bool{u.ID: true}
	for i, pct := range tiers {
		if upline == "" || seen[upline] {
			break // no more upline, or cycle guard
		}
		seen[upline] = true
		if pct > 0 {
			reward := amount * pct / 100
			if reward > 0 {
				grant(db, upline, u.ID, i+1, "percent", amount, reward, refID)
			}
		}
		upline = parentOf(db, upline)
	}
}

// payFixed pays the direct upline once, after the invitee's total recharges
// reach the qualify threshold. The unique index on (user_id, from_user_id) for
// mode=fixed makes this idempotent.
func payFixed(db *store.DB, u store.User, refID string) {
	qualify := db.Settings().GetInt(store.SettingReferralQualify, 0)
	var total int64
	_ = db.SQL().QueryRow(
		`SELECT COALESCE(SUM(delta),0) FROM credit_ledger WHERE user_id = ? AND reason = 'recharge' AND delta > 0`,
		u.ID).Scan(&total)
	if qualify > 0 && total < qualify {
		return
	}
	fixed := db.Settings().GetInt(store.SettingReferralFixed, 0)
	if fixed <= 0 || u.ReferredBy == "" {
		return
	}
	grant(db, u.ReferredBy, u.ID, 1, "fixed", 0, fixed, refID)
}

// grant records the earning first (unique index guards fixed-mode replays),
// then credits the upline wallet.
func grant(db *store.DB, uplineID, fromID string, tier int, mode string, base, reward int64, refID string) {
	res, errExec := db.SQL().Exec(`
		INSERT INTO referral_earnings (user_id, from_user_id, tier, mode, base_amount, reward, ref_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uplineID, fromID, tier, mode, base, reward, nullStr(refID), store.Now())
	if errExec != nil {
		if store.IsDuplicate(errExec) {
			return // fixed-mode: already rewarded for this pair
		}
		log.Printf("[mkp] referral earnings insert: %v", errExec)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return
	}
	if _, errAdj := db.Users().AdjustBalance(uplineID, reward, store.ReasonReferralBonus, refID+":ref", "system", ""); errAdj != nil {
		log.Printf("[mkp] referral credit: %v", errAdj)
	}
}

func parentOf(db *store.DB, userID string) string {
	var parent sql.NullString
	if err := db.SQL().QueryRow(`SELECT referred_by FROM users WHERE id = ?`, userID).Scan(&parent); err != nil {
		return ""
	}
	return parent.String
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
