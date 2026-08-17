// Package billing implements token-based charging with three anti-duplicate rules
// verified by the PoC run (2026-08-18, see cpa-research-findings.md §13b):
//
//  1. Charge by tokens, not hook invocations — CPA retries create multiple
//     usage.handle calls with Failed=true and TotalTokens=0; charging per call
//     would bill customers 2x for a single failed request.
//
//  2. Aggregate request quota by client_request_id — one client question may hit
//     several upstream accounts (fallback), but counts as one "request" toward a
//     request-scoped quota.
//
//  3. Hold once at intercept_before, settle at usage.handle — intercept_before runs
//     once per client request; intercept_after runs per attempt (PoC saw 3 after-calls
//     for 2 usage records on a failed request).
//
// For v0.1, we skip the hold mechanism and settle directly at usage.handle, which
// means no reservation against concurrent requests. That's acceptable for initial
// rollout; the full hold/settle flow comes in v0.2.
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
	Alias       string `json:"Alias"`       // what the client asked for
	APIKey      string `json:"APIKey"`      // equals Principal from frontend_auth
	AuthID      string `json:"AuthID"`      // "provider:kind:id"
	AuthIndex   string `json:"AuthIndex"`   // CPA's index into its config
	AuthType    string `json:"AuthType"`    // "api-key" | "oauth"
	Failed      bool   `json:"Failed"`      // true when upstream errored
	RequestedAt string `json:"RequestedAt"` // RFC3339

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
// three anti-duplicate rules and returns the cost in micro-credit.
func Charge(db *store.DB, rec UsageRecord) (int64, error) {
	// Rule 1: charge by tokens, not hook invocations.
	if rec.Detail.TotalTokens == 0 {
		// Failed attempt with no upstream response, or a non-billable call like /v1/models.
		// Log it but don't charge.
		log.Printf("[mkp] usage %s: no tokens, skipping charge (failed=%v)", rec.APIKey, rec.Failed)
		return 0, nil
	}

	// Lookup the key. APIKey is the Principal we returned in frontend_auth.
	key, errKey := db.Keys().ByID(rec.APIKey)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			// Key was deleted between auth and usage — log and skip.
			log.Printf("[mkp] usage: key %s not found, skipping charge", rec.APIKey)
			return 0, nil
		}
		return 0, fmt.Errorf("lookup key for usage: %w", errKey)
	}

	// TODO: load pricing from the pricing table and compute cost.
	// For v0.1, use a placeholder: 1 token = 1 micro-credit (unrealistic but testable).
	cost := rec.Detail.TotalTokens

	// TODO: Rule 2 — aggregate request-scoped quota by client_request_id.
	// For v0.1, we treat every usage.handle independently, which over-counts
	// request quota during fallback. Acceptable for initial rollout.

	// Decide where to charge: key quota or wallet.
	var source string
	if key.HasQuota() {
		// Key quota covers it.
		if errConsume := db.Keys().ConsumeQuota(key.ID, cost); errConsume != nil {
			return 0, fmt.Errorf("consume key quota: %w", errConsume)
		}
		source = "key_quota"
		log.Printf("[mkp] charged %s: %d from key quota (%s)", key.ID, cost, key.QuotaKind)
	} else if key.OverflowToWallet {
		// Key exhausted, overflow to wallet.
		user, errUser := db.Users().ByID(key.UserID)
		if errUser != nil {
			return 0, fmt.Errorf("lookup user for wallet: %w", errUser)
		}
		if !user.CanSpend(cost) {
			// Wallet insufficient. For v0.1, we still record the usage but mark it
			// unbilled so the admin can decide (refund, topup, etc.).
			log.Printf("[mkp] insufficient wallet for %s: need %d, have %d", user.ID, cost, user.Balance)
			source = "" // unbilled
		} else {
			// Debit wallet.
			refID := fmt.Sprintf("usage_%d", store.Now())
			if _, errAdjust := db.Users().AdjustBalance(user.ID, -cost, store.ReasonUsage, refID, "system", key.ID); errAdjust != nil {
				return 0, fmt.Errorf("debit wallet: %w", errAdjust)
			}
			source = "wallet"
			log.Printf("[mkp] charged %s: %d from wallet", user.ID, cost)
		}
	} else {
		// Key exhausted, overflow disabled — reject.
		log.Printf("[mkp] key %s exhausted, overflow disabled", key.ID)
		return 0, fmt.Errorf("key quota exhausted")
	}

	// Record the usage for audit and analytics.
	billed := 1
	if source == "" {
		billed = 0
	}
	if errRecord := recordUsage(db, key, rec, cost, source, billed); errRecord != nil {
		log.Printf("[mkp] record usage: %v", errRecord)
		// Non-fatal: the charge went through, we just failed to log it.
	}

	return cost, nil
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
			cost, source, billed, status, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.UserID, rec.Provider, rec.Model, rec.Alias, rec.AuthID,
		rec.Detail.InputTokens, rec.Detail.OutputTokens, rec.Detail.ReasoningTokens, rec.Detail.CachedTokens,
		rec.Detail.CacheReadTokens, rec.Detail.CacheCreationTokens,
		cost, nullIfEmpty(source), billed, status, store.Now())
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
