package billing

import (
	"fmt"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Price holds per-model micro-credit pricing. Values are micro-credit per token
// (i.e. per-token cost scaled by 1e6).
type Price struct {
	Model              string
	InputPerToken      int64   `json:"input_per_token"`
	OutputPerToken     int64   `json:"output_per_token"`
	ReasoningPerToken  int64   `json:"reasoning_per_token"`
	CacheReadPerToken  int64   `json:"cache_read_per_token"`
	CacheWritePerToken int64   `json:"cache_write_per_token"`
	HoldMultiplier     float64 `json:"hold_multiplier"`
}

// DefaultPrices returns a sensible default pricing table in micro-credit per token.
// These are approximate values for Anthropic models at ~1 USD = 1 credit.
func DefaultPrices() map[string]Price {
	// 1 USD = 1,000,000 micro-credit
	// Claude Sonnet 5:  input $3/M  = 3/1_000_000 USD/token = 3_000_000 micro/M = 3 micro/token
	//                   output $15/M = 15 micro/token
	return map[string]Price{
		"claude-sonnet-5": {
			Model:              "claude-sonnet-5",
			InputPerToken:      3,
			OutputPerToken:     15,
			ReasoningPerToken:  15,
			CacheReadPerToken:  1, // ~10% of input for Anthropic cache reads (rounded)
			CacheWritePerToken: 4, // ~125% of input for cache writes (rounded)
			HoldMultiplier:     1.5,
		},
		"claude-opus-5": {
			Model:              "claude-opus-5",
			InputPerToken:      15,
			OutputPerToken:     75,
			ReasoningPerToken:  75,
			CacheReadPerToken:  2,
			CacheWritePerToken: 19,
			HoldMultiplier:     1.5,
		},
		"claude-haiku-5": {
			Model:              "claude-haiku-5",
			InputPerToken:      1,
			OutputPerToken:     4,
			ReasoningPerToken:  4,
			CacheReadPerToken:  1,
			CacheWritePerToken: 1,
			HoldMultiplier:     1.5,
		},
	}
}

// LoadPrice looks up the price for a model. Falls back to DefaultPrices when the
// DB pricing table is empty.
func LoadPrice(db *store.DB, model string) (Price, error) {
	// First try the pricing table.
	var p Price
	errQuery := db.SQL().QueryRow(`
		SELECT model, input_per_mtok, output_per_mtok, reasoning_per_mtok,
			cache_read_per_mtok, cache_write_per_mtok, hold_multiplier
		FROM pricing WHERE model = ?`, model).
		Scan(&p.Model, &p.InputPerToken, &p.OutputPerToken, &p.ReasoningPerToken,
			&p.CacheReadPerToken, &p.CacheWritePerToken, &p.HoldMultiplier)
	if errQuery == nil {
		// pricing table stores per-Mtok; convert to per-token.
		p.InputPerToken = p.InputPerToken / 1000000
		p.OutputPerToken = p.OutputPerToken / 1000000
		p.ReasoningPerToken = p.ReasoningPerToken / 1000000
		p.CacheReadPerToken = p.CacheReadPerToken / 1000000
		p.CacheWritePerToken = p.CacheWritePerToken / 1000000
		return p, nil
	}

	// Fall back to defaults.
	defaults := DefaultPrices()
	if dp, ok := defaults[model]; ok {
		return dp, nil
	}

	// Fallback: look for any model that starts with the same family.
	family := strings.Split(model, "-")[0]
	for key, dp := range defaults {
		if strings.HasPrefix(key, family) {
			return dp, nil
		}
	}

	// Absolute fallback: use sonnet pricing.
	return Price{
		Model:          model,
		InputPerToken:  3,
		OutputPerToken: 15,
		HoldMultiplier: 1.5,
	}, nil
}

// ComputeCost calculates the micro-credit cost for a usage record given the price.
// It applies cache-aware billing:
//   - Anthropic: cache tokens are ADDITIVE (not included in input_tokens).
//   - OpenAI/Gemini: cache tokens are SUBSET (already included in input_tokens).
func ComputeCost(rec UsageRecord, price Price) int64 {
	input := rec.Detail.InputTokens
	output := rec.Detail.OutputTokens
	reasoning := rec.Detail.ReasoningTokens
	cacheRead := rec.Detail.CacheReadTokens
	cacheWrite := rec.Detail.CacheCreationTokens

	// Determine if this provider uses additive cache accounting.
	// Anthropic: cache tokens are separate from input_tokens.
	// OpenAI/Gemini: cache tokens are already included in input_tokens.
	isAdditive := isCacheAdditive(rec.Provider)

	if isAdditive {
		// Anthropic: cache_read and cache_write are on top of input.
		cost := input*price.InputPerToken +
			output*price.OutputPerToken +
			reasoning*price.ReasoningPerToken +
			cacheRead*price.CacheReadPerToken +
			cacheWrite*price.CacheWritePerToken
		return cost
	}

	// Subset providers (OpenAI, Gemini): cache tokens already in input.
	// Only add reasoning on top of input.
	cost := input*price.InputPerToken +
		output*price.OutputPerToken +
		reasoning*price.ReasoningPerToken
	return cost
}

// isCacheAdditive reports whether cache tokens are added on top of input_tokens.
// Anthropic: cache_read_tokens and cache_creation_tokens are separate.
// OpenAI/Gemini: cached tokens are included in input_tokens.
func isCacheAdditive(provider string) bool {
	provider = strings.ToLower(provider)
	return provider == "anthropic" || provider == "claude"
}

// SeedPricing populates the pricing table with DefaultPrices if empty.
func SeedPricing(db *store.DB) error {
	var count int
	if errQuery := db.SQL().QueryRow(`SELECT COUNT(1) FROM pricing`).Scan(&count); errQuery != nil {
		return fmt.Errorf("count pricing: %w", errQuery)
	}
	if count > 0 {
		return nil
	}
	defaults := DefaultPrices()
	for _, p := range defaults {
		// Convert per-token to per-Mtok for storage.
		inputMtok := p.InputPerToken * 1000000
		outputMtok := p.OutputPerToken * 1000000
		reasoningMtok := p.ReasoningPerToken * 1000000
		cacheReadMtok := int64(p.CacheReadPerToken * 1000000)
		cacheWriteMtok := int64(p.CacheWritePerToken * 1000000)
		if _, errExec := db.SQL().Exec(`
			INSERT INTO pricing (model, input_per_mtok, output_per_mtok, reasoning_per_mtok,
				cache_read_per_mtok, cache_write_per_mtok, hold_multiplier, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.Model, inputMtok, outputMtok, reasoningMtok,
			cacheReadMtok, cacheWriteMtok, p.HoldMultiplier, store.Now()); errExec != nil {
			return fmt.Errorf("seed pricing %s: %w", p.Model, errExec)
		}
		log.Printf("[mkp] seeded pricing for %s", p.Model)
	}
	return nil
}
