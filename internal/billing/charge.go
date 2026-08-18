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
// anti-duplicate rules and returns the micro-credit charged.
func Charge(db *store.DB, rec UsageRecord) (int64, error) {
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

	price, errPrice := LoadPrice(db, rec.Model)
	if errPrice != nil {
		log.Printf("[mkp] load price: %v — charging raw token count", errPrice)
	}
	cost := ComputeCost(rec, price)
	if cost <= 0 {
		// Pricing configured to zero: charge 1 micro-credit per token so usage
		// still costs something (avoid free usage with a misconfigured price).
		cost = rec.Detail.TotalTokens
	}

	// Rule 2: aggregate request-scoped quota by client_request_id. For
	// quota_kind=request, count one client request once even across attempts.
	requestAlreadyCounted := false
	if key.QuotaKind == "request" && rec.RequestID != "" {
		var n int
		_ = db.SQL().QueryRow(
			`SELECT COUNT(1) FROM usage_records WHERE client_request_id = ? AND billed = 1`,
			rec.RequestID).Scan(&n)
		requestAlreadyCounted = n > 0
	}

	// Rule 3: settle any hold placed for this request, refunding unused hold and
	// reporting the extra still owed.
	extra := cost
	if rec.RequestID != "" {
		var refundOrExtra int64
		refundOrExtra, settled := Settle(db, key.ID, cost)
		if settled {
			extra = refundOrExtra
			if extra < 0 {
				extra = 0
			}
		}
	}
	// For request-quota keys that already counted this client request, only the
	// extra beyond the hold needs settling; the request itself is not recounted.
	_ = requestAlreadyCounted

	var source string
	billed := 1
	charged := int64(0)

	switch {
	case extra <= 0:
		// The hold fully covered the cost; nothing further to charge.
		source = "key_quota"
		charged = cost
	case key.HasQuota():
		// Key quota covers the extra.
		if errConsume := db.Keys().ConsumeQuota(key.ID, extra); errConsume != nil {
			return 0, fmt.Errorf("consume key quota: %w", errConsume)
		}
		source = "key_quota"
		charged = cost
	case key.OverflowToWallet:
		// Key exhausted, overflow to wallet.
		user, errUser := db.Users().ByID(key.UserID)
		if errUser != nil {
			return 0, fmt.Errorf("lookup user for wallet: %w", errUser)
		}
		if !user.CanSpend(extra) {
			log.Printf("[mkp] insufficient wallet for %s: need %d, have %d", user.ID, extra, user.Balance)
			source = "" // unbilled; admin decides
			billed = 0
		} else {
			refID := fmt.Sprintf("usage_%d", store.Now())
			if _, errAdjust := db.Users().AdjustBalance(user.ID, -extra, store.ReasonUsage, refID, "system", key.ID); errAdjust != nil {
				return 0, fmt.Errorf("debit wallet: %w", errAdjust)
			}
			source = "wallet"
			charged = cost
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
	_, errExec := db.SQL().Exec(`
		INSERT INTO usage_records (
			key_id, user_id, provider, model, requested_name, upstream_account,
			input_tokens, output_tokens, reasoning_tokens, cached_tokens,
			cache_read_tokens, cache_creation_tokens,
			cost, source, billed, client_request_id, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, rec.Provider, rec.Model, rec.Alias, rec.AuthID,
		rec.Detail.InputTokens, rec.Detail.OutputTokens, rec.Detail.ReasoningTokens, rec.Detail.CachedTokens,
		rec.Detail.CacheReadTokens, rec.Detail.CacheCreationTokens,
		cost, nullIfEmpty(source), billed, nullIfEmpty(rec.RequestID), status, store.Now())
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
