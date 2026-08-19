package billing

import (
	"database/sql"
	"log"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// DefaultHoldMicro is the base hold (0.5 credit) when pricing has no per-call value.
const DefaultHoldMicro float64 = 500_000

// DefaultHoldTokens is the token hold for token-kind keys (30k tokens ~ an
// average request with some reasoning) when we have no better estimate.
const DefaultHoldTokens int64 = 30_000

// HoldAmount estimates how much to reserve for one request of the given model,
// in the unit of the key's quota kind: micro-credit for credit, tokens for
// token, 1 for request. Unlimited reserves nothing.
func HoldAmount(db *store.DB, key store.Key, model string) int64 {
	switch key.QuotaKind {
	case "unlimited":
		return 0
	case "token":
		// Rough upper bound of tokens in one request.
		return DefaultHoldTokens
	case "request":
		return 1
	default: // credit
		price, errPrice := LoadPrice(db, model)
		base := DefaultHoldMicro
		if errPrice == nil && price.PerCallCredit > 0 {
			base = price.PerCallCredit
		}
		mult := price.HoldMultiplier
		if mult <= 0 {
			mult = 1.5
		}
		return int64(base * mult)
	}
}

// Hold creates an open reservation for one client request, in the unit of the
// key's quota kind. It reserves from the key quota first; when the key is
// exhausted and overflow is enabled it reserves micro-credit from the wallet
// (wallet is always credit). Never blocks the request: any error just skips
// the hold (settle/release still work without one).
func Hold(db *store.DB, requestID, keyID, userID, model string) {
	if requestID == "" || keyID == "" {
		return
	}
	key, errKey := db.Keys().ByID(keyID)
	if errKey != nil {
		return
	}
	if errPeriod := EnsurePeriod(db, &key); errPeriod != nil {
		log.Printf("[mkp] hold ensure period: %v", errPeriod)
	}
	hold := HoldAmount(db, key, model)
	source := ""
	amount := int64(0)

	switch {
	case key.QuotaKind == "unlimited":
		source = "key_quota"
		amount = 0
	case key.HasQuota():
		// Reserve out of the key quota (capped at what remains).
		amount = hold
		if rem := key.QuotaRemaining(); rem < amount {
			amount = rem
		}
		if amount > 0 {
			if errConsume := db.Keys().ConsumeQuota(keyID, amount); errConsume != nil {
				log.Printf("[mkp] hold consume quota: %v", errConsume)
				return
			}
		}
		source = "key_quota"
	case key.OverflowToWallet:
		// Wallet is always micro-credit; estimate the hold in credit from pricing.
		user, errUser := db.Users().ByID(userID)
		if errUser != nil {
			return
		}
		holdMicro := HoldAmount(db, store.Key{QuotaKind: "credit"}, model)
		if !user.CanSpend(holdMicro) {
			return // wallet cannot cover the hold; usage-time charge will 402
		}
		refID := "hold:" + requestID
		if _, errAdj := db.Users().AdjustBalance(userID, -holdMicro, store.ReasonHold, refID, "system", keyID); errAdj != nil {
			log.Printf("[mkp] hold wallet: %v", errAdj)
			return
		}
		source = "wallet"
		amount = holdMicro
	default:
		return // exhausted, no overflow — nothing to hold
	}

	if _, errExec := db.SQL().Exec(`
		INSERT OR REPLACE INTO reservations (reservation_id, key_id, user_id, model, hold, source, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, 'open', ?)`,
		requestID, keyID, userID, model, amount, source, store.Now()); errExec != nil {
		log.Printf("[mkp] hold insert reservation: %v", errExec)
	}
}

// Settle finalizes the reservation for a client request once the real spend
// (in the key's quota unit) is known. It refunds the unused part of the hold
// back to its source and reports any ADDITIONAL amount still owed beyond the
// hold (the caller charges that via the normal quota/wallet path).
// Returns extra >= 0.
func Settle(db *store.DB, keyID string, actualSpend int64) (extra int64, settled bool) {
	var resID, source string
	var hold int64
	errRow := db.SQL().QueryRow(`
		SELECT reservation_id, source, hold FROM reservations
		WHERE key_id = ? AND status = 'open'
		ORDER BY created_at ASC LIMIT 1`, keyID).Scan(&resID, &source, &hold)
	if errRow != nil {
		return actualSpend, false // no open reservation: charge the full cost
	}

	extra = actualSpend - hold
	if extra < 0 {
		extra = 0
	}
	refund := hold - actualSpend
	if refund < 0 {
		refund = 0
	}

	switch source {
	case "wallet":
		if refund > 0 {
			var userID string
			_ = db.SQL().QueryRow(`SELECT user_id FROM reservations WHERE reservation_id = ?`, resID).Scan(&userID)
			if userID != "" {
				refID := "settle:" + resID
				if _, errAdj := db.Users().AdjustBalance(userID, refund, store.ReasonRefund, refID, "system", keyID); errAdj != nil {
					log.Printf("[mkp] settle refund: %v", errAdj)
				}
			}
		}
	case "key_quota":
		if refund > 0 {
			// Give the unused quota back (ConsumeQuota with a negative delta).
			if errConsume := db.Keys().ConsumeQuota(keyID, -refund); errConsume != nil {
				log.Printf("[mkp] settle refund quota: %v", errConsume)
			}
		}
	}

	if _, errExec := db.SQL().Exec(
		`UPDATE reservations SET status = 'settled' WHERE reservation_id = ?`, resID); errExec != nil {
		log.Printf("[mkp] settle mark: %v", errExec)
	}
	return extra, true
}

// Release gives the whole hold back. Called from request.complete for requests
// that never produced a usage record (timeouts, rejects, cancels).
func Release(db *store.DB, requestID string) {
	if requestID == "" {
		return
	}
	var keyID, userID, source string
	var hold int64
	var status string
	errRow := db.SQL().QueryRow(`
		SELECT key_id, user_id, source, hold, status FROM reservations WHERE reservation_id = ?`,
		requestID).Scan(&keyID, &userID, &source, &hold, &status)
	if errRow != nil {
		if errRow != sql.ErrNoRows {
			log.Printf("[mkp] release lookup: %v", errRow)
		}
		return
	}
	if status != "open" || hold <= 0 {
		return
	}
	switch source {
	case "wallet":
		refID := "release:" + requestID
		if _, errAdj := db.Users().AdjustBalance(userID, hold, store.ReasonRefund, refID, "system", keyID); errAdj != nil {
			log.Printf("[mkp] release refund: %v", errAdj)
		}
	case "key_quota":
		if errConsume := db.Keys().ConsumeQuota(keyID, -hold); errConsume != nil {
			log.Printf("[mkp] release refund quota: %v", errConsume)
		}
	}
	if _, errExec := db.SQL().Exec(
		`UPDATE reservations SET status = 'released' WHERE reservation_id = ?`, requestID); errExec != nil {
		log.Printf("[mkp] release mark: %v", errExec)
	}
}

// ReleaseStale frees reservations left open after a crash (older than maxAgeMs).
// Called once at boot.
func ReleaseStale(db *store.DB, maxAgeMs int64) {
	rows, errQuery := db.SQL().Query(`
		SELECT reservation_id FROM reservations
		WHERE status = 'open' AND created_at < ?`, store.Now()-maxAgeMs)
	if errQuery != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if errScan := rows.Scan(&id); errScan == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		Release(db, id)
	}
	if len(ids) > 0 {
		log.Printf("[mkp] released %d stale reservations", len(ids))
	}
}
