// Package billing implements token-based charging with the three anti-duplicate
// rules verified by the PoC run (cpa-research-findings.md §13b):
//
//  1. Charge by tokens, not hook invocations — CPA retries create multiple
//     usage.handle calls with Failed=true and TotalTokens=0; charging per call
//     would bill customers 2x for a single failed request.
//  2. Aggregate request quota by client_request_id — one client question may hit
//     several upstream accounts (fallback), but counts as one "request" toward a
//     request-scoped quota.
//  3. Hold once at intercept_before, settle at usage.handle — intercept_before runs
//     once per client request; intercept_after runs per attempt.
package billing

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// UsageRecord mirrors the payload CPA sends to usage.handle.
type UsageRecord struct {
	Provider    string `json:"Provider"`
	Model       string `json:"Model"`
	Alias       string `json:"Alias"`  // what the client asked for
	APIKey      string `json:"APIKey"` // equals Principal (key.ID) from frontend_auth
	AuthID      string `json:"AuthID"` // "provider:kind:id"
	AuthIndex   string `json:"AuthIndex"`
	AuthType    string `json:"AuthType"`
	Failed      bool   `json:"Failed"`
	RequestedAt string `json:"RequestedAt"`
	RequestID   string `json:"RequestID"` // correlates hold/settle/release
	// Latency / TTFT are nanoseconds when CPA provides them.
	Latency int64 `json:"Latency"`
	TTFT    int64 `json:"TTFT"`

	Detail struct {
		InputTokens         int64 `json:"InputTokens"`
		OutputTokens        int64 `json:"OutputTokens"`
		ReasoningTokens     int64 `json:"ReasoningTokens"`
		CachedTokens        int64 `json:"CachedTokens"`
		CacheReadTokens     int64 `json:"CacheReadTokens"`
		CacheCreationTokens int64 `json:"CacheCreationTokens"`
		TotalTokens         int64 `json:"TotalTokens"`
	} `json:"Detail"`
}

// Charge applies the usage record to the key's quota or wallet. It enforces the
// anti-duplicate rules and returns the micro-credit charged (for display) and
// the unit spend applied to the key (tokens / requests / micro-credit).
func Charge(db *store.DB, rec UsageRecord) (costMicro int64, err error) {
	// Rule 1: charge by tokens, not hook invocations.
	if rec.Detail.TotalTokens == 0 {
		// Failed attempt before any tokens, or a non-billable call (/v1/models).
		// Record it as unbilled for the logs, do not charge.
		key, errKey := db.Keys().ByID(rec.APIKey)
		if errKey == nil {
			_ = recordUsage(db, key, rec, 0, "", 0)
		}
		return 0, nil
	}

	key, errKey := db.Keys().ByID(rec.APIKey)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			log.Printf("[mkp] usage: key %s not found, skipping charge", rec.APIKey)
			return 0, nil
		}
		return 0, fmt.Errorf("lookup key for usage: %w", errKey)
	}
	if errPeriod := EnsurePeriod(db, &key); errPeriod != nil {
		log.Printf("[mkp] charge ensure period: %v", errPeriod)
	}

	price, errPrice := LoadPrice(db, rec.Model)
	if errPrice != nil {
		log.Printf("[mkp] load price: %v — charging raw token count as micro", errPrice)
	}
	costMicro = ComputeCost(rec, price)
	if costMicro <= 0 {
		// Pricing configured to zero: charge 1 micro-credit per token so usage
		// still costs something (avoid free usage with a misconfigured price).
		costMicro = rec.Detail.TotalTokens
	}

	// Unit spend in the key's quota unit.
	unitSpend := costMicro
	switch key.QuotaKind {
	case "token":
		unitSpend = rec.Detail.TotalTokens
	case "request":
		// Rule 2: one client request counts once toward request-quota.
		if rec.RequestID != "" {
			var n int
			_ = db.SQL().QueryRow(
				`SELECT COUNT(1) FROM usage_records WHERE client_request_id = ? AND billed = 1 AND key_id = ?`,
				rec.RequestID, key.ID).Scan(&n)
			if n > 0 {
				// Already counted this client request. Still settle any hold and
				// record the usage, but do not consume another request unit.
				unitSpend = 0
			} else {
				unitSpend = 1
			}
		} else {
			unitSpend = 1
		}
	case "unlimited":
		unitSpend = 0
	}

	// Rule 3: settle any hold placed for this request. Hold is in the same unit
	// as unitSpend for key_quota; for wallet holds it is micro-credit so we
	// settle against costMicro when source=wallet (handled inside Settle by
	// comparing hold vs actualSpend for that source). For simplicity we settle
	// with unitSpend for key_quota holds and costMicro when no key hold.
	extra := unitSpend
	if rec.RequestID != "" {
		// Prefer settle by reservation_id so multi-key never mixes.
		var source string
		_ = db.SQL().QueryRow(
			`SELECT source FROM reservations WHERE reservation_id = ? AND status = 'open'`,
			rec.RequestID).Scan(&source)
		actual := unitSpend
		if source == "wallet" {
			actual = costMicro
		}
		var refundOrExtra int64
		var settled bool
		// Settle looks up by key_id; pass actual in the unit of that hold.
		refundOrExtra, settled = Settle(db, key.ID, actual)
		if settled {
			extra = refundOrExtra
			if extra < 0 {
				extra = 0
			}
			// For wallet holds, extra is still micro-credit — convert to unit
			// for key path is not needed because wallet path charges micro.
			if source == "wallet" {
				// Already settled wallet hold; charge only extra micro if any.
				if extra > 0 {
					user, errUser := db.Users().ByID(key.UserID)
					if errUser == nil && user.CanSpend(extra) {
						refID := fmt.Sprintf("usage_%d", store.Now())
						if _, errAdjust := db.Users().AdjustBalance(user.ID, -extra, store.ReasonUsage, refID, "system", key.ID); errAdjust != nil {
							return 0, fmt.Errorf("debit wallet extra: %w", errAdjust)
						}
					}
				}
				if errRecord := recordUsage(db, key, rec, costMicro, "wallet", 1); errRecord != nil {
					log.Printf("[mkp] record usage: %v", errRecord)
				}
				return costMicro, nil
			}
		}
	}

	var source string
	billed := 1
	charged := int64(0)

	switch {
	case key.QuotaKind == "unlimited":
		source = "key_quota"
		charged = costMicro
	case extra <= 0:
		// The hold fully covered the unit spend; nothing further to charge.
		source = "key_quota"
		charged = costMicro
	case key.HasQuota() && key.QuotaRemaining() >= extra:
		if errConsume := db.Keys().ConsumeQuota(key.ID, extra); errConsume != nil {
			return 0, fmt.Errorf("consume key quota: %w", errConsume)
		}
		source = "key_quota"
		charged = costMicro
	case key.OverflowToWallet:
		// Key exhausted (or not enough remaining). Overflow to wallet in micro-credit.
		user, errUser := db.Users().ByID(key.UserID)
		if errUser != nil {
			return 0, fmt.Errorf("lookup user for wallet: %w", errUser)
		}
		// For token/request kinds the wallet charges the micro cost, not the unit.
		walletCharge := costMicro
		if !user.CanSpend(walletCharge) {
			log.Printf("[mkp] insufficient wallet for %s: need %d, have %d", user.ID, walletCharge, user.Balance)
			source = ""
			billed = 0
		} else {
			refID := fmt.Sprintf("usage_%d", store.Now())
			if _, errAdjust := db.Users().AdjustBalance(user.ID, -walletCharge, store.ReasonUsage, refID, "system", key.ID); errAdjust != nil {
				return 0, fmt.Errorf("debit wallet: %w", errAdjust)
			}
			source = "wallet"
			charged = costMicro
		}
	default:
		log.Printf("[mkp] key %s exhausted, overflow disabled", key.ID)
		source = ""
		billed = 0
	}

	if errRecord := recordUsage(db, key, rec, charged, source, billed); errRecord != nil {
		log.Printf("[mkp] record usage: %v", errRecord)
	}
	return charged, nil
}

func recordUsage(db *store.DB, key store.Key, rec UsageRecord, cost int64, source string, billed int) error {
	status := "ok"
	if rec.Failed {
		status = "failed"
	}
	ttftMs := int64(0)
	latMs := int64(0)
	if rec.TTFT > 0 {
		ttftMs = rec.TTFT / 1_000_000
	}
	if rec.Latency > 0 {
		latMs = rec.Latency / 1_000_000
	}
	_, errExec := db.SQL().Exec(`
		INSERT INTO usage_records (
			key_id, user_id, provider, model, requested_name, upstream_account,
			input_tokens, output_tokens, reasoning_tokens, cached_tokens,
			cache_read_tokens, cache_creation_tokens,
			cost, source, billed, client_request_id, status, ttft_ms, latency_ms, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, rec.Provider, rec.Model, rec.Alias, rec.AuthID,
		rec.Detail.InputTokens, rec.Detail.OutputTokens, rec.Detail.ReasoningTokens, rec.Detail.CachedTokens,
		rec.Detail.CacheReadTokens, rec.Detail.CacheCreationTokens,
		cost, nullIfEmpty(source), billed, nullIfEmpty(rec.RequestID), status,
		nullInt64(ttftMs), nullInt64(latMs), store.Now())
	if errExec != nil {
		return fmt.Errorf("insert usage_records: %w", errExec)
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt64(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// HandleUsageJSON is the public entry point called by plugin.handleUsage.
func HandleUsageJSON(db *store.DB, payload []byte) error {
	var rec UsageRecord
	if errUnmarshal := json.Unmarshal(payload, &rec); errUnmarshal != nil {
		return fmt.Errorf("unmarshal usage: %w", errUnmarshal)
	}
	if _, errCharge := Charge(db, rec); errCharge != nil {
		return fmt.Errorf("charge: %w", errCharge)
	}
	return nil
}
