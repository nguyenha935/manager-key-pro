package billing

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// DefaultHoldMicro is the base hold (0.5 credit) when pricing has no per-call value.
const DefaultHoldMicro int64 = 500_000

// HoldAmount estimates how much to reserve for one request of the given model:
// base (per-call credit when configured, else DefaultHoldMicro) x hold_multiplier.
func HoldAmount(db *store.DB, model string) int64 {
	price, errPrice := LoadPrice(db, model)
	base := DefaultHoldMicro
	if errPrice == nil && price.PerCallCredit > 0 {
		base = price.PerCallCredit
	}
	mult := price.HoldMultiplier
	if mult <= 0 {
		mult = 1.5
	}
	return int64(float64(base) * mult)
}

// Hold creates an open reservation for one client request. It reserves from the
// key quota first; when the key is exhausted and overflow is enabled it reserves
// from the wallet instead. Never blocks the request: any error just skips the hold
// (settle/release still work without one).
func Hold(db *store.DB, requestID, keyID, userID, model string) {
	if requestID == "" || keyID == "" {
		return
	}
	key, errKey := db.Keys().ByID(keyID)
	if errKey != nil {
		return
	}
	hold := HoldAmount(db, model)
	source := ""
	amount := int64(0)

	switch {
	case key.QuotaKind == "unlimited":
		// Nothing to reserve; record the reservation for tracking only.
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
		user, errUser := db.Users().ByID(userID)
		if errUser != nil {
			return
		}
		if !user.CanSpend(hold) {
			return // wallet cannot cover the hold; usage-time charge will 402
		}
		refID := "hold:" + requestID
		if _, errAdj := db.Users().AdjustBalance(userID, -hold, store.ReasonHold, refID, "system", keyID); errAdj != nil {
			log.Printf("[mkp] hold wallet: %v", errAdj)
			return
		}
		source = "wallet"
		amount = hold
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

// Settle finalizes the reservation for a client request once the real cost is
// known. It refunds the unused part of the hold back to its source and reports
// any ADDITIONAL amount still owed beyond the hold (the caller charges that via
// the normal quota/wallet path). Returns extra >= 0.
func Settle(db *store.DB, keyID string, actualCost int64) (extra int64, settled bool) {
	var resID, source string
	var hold int64
	errRow := db.SQL().QueryRow(`
		SELECT reservation_id, source, hold FROM reservations
		WHERE key_id = ? AND status = 'open'
		ORDER BY created_at ASC LIMIT 1`, keyID).Scan(&resID, &source, &hold)
	if errRow != nil {
		return actualCost, false // no open reservation: charge the full cost
	}

	extra = actualCost - hold
	if extra < 0 {
		extra = 0
	}
	refund := hold - actualCost
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

var _ = fmt.Sprintf // keep fmt for future use
