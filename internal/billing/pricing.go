package billing

import (
	"fmt"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Price holds per-model pricing in micro-credit PER MILLION TOKENS. The DB's
// pricing table stores REAL columns, so the per-token fields are float64 to
// scan cleanly (int64 scan of REAL crashed: "1e+06" -> int64). PerCallCredit
// is an optional flat micro-credit charge per call (used for hold).
type Price struct {
	Model             string
	InputPerMtok      float64 `json:"input_per_mtok"`
	OutputPerMtok     float64 `json:"output_per_mtok"`
	ReasoningPerMtok  float64 `json:"reasoning_per_mtok"`
	CacheReadPerMtok  float64 `json:"cache_read_per_mtok"`
	CacheWritePerMtok float64 `json:"cache_write_per_mtok"`
	PerCallCredit     float64 `json:"per_call_credit"`
	HoldMultiplier    float64 `json:"hold_multiplier"`
}

// DefaultPrices returns sensible defaults in micro-credit per million tokens.
// 1 USD = 1,000,000 micro-credit.
func DefaultPrices() map[string]Price {
	return map[string]Price{
		"claude-sonnet-5": {Model: "claude-sonnet-5", InputPerMtok: 3_000_000, OutputPerMtok: 15_000_000, ReasoningPerMtok: 15_000_000, CacheReadPerMtok: 1_000_000, CacheWritePerMtok: 4_000_000, HoldMultiplier: 1.5},
		"claude-opus-5":   {Model: "claude-opus-5", InputPerMtok: 15_000_000, OutputPerMtok: 75_000_000, ReasoningPerMtok: 75_000_000, CacheReadPerMtok: 2_000_000, CacheWritePerMtok: 19_000_000, HoldMultiplier: 1.5},
		"claude-haiku-5":  {Model: "claude-haiku-5", InputPerMtok: 1_000_000, OutputPerMtok: 4_000_000, ReasoningPerMtok: 4_000_000, CacheReadPerMtok: 1_000_000, CacheWritePerMtok: 1_000_000, HoldMultiplier: 1.5},
	}
}

const priceColumns = `model, input_per_mtok, output_per_mtok, reasoning_per_mtok,
	cache_read_per_mtok, cache_write_per_mtok, COALESCE(per_call_credit,0), hold_multiplier`

func scanPrice(row interface{ Scan(...any) error }) (Price, error) {
	var p Price
	err := row.Scan(&p.Model, &p.InputPerMtok, &p.OutputPerMtok, &p.ReasoningPerMtok,
		&p.CacheReadPerMtok, &p.CacheWritePerMtok, &p.PerCallCredit, &p.HoldMultiplier)
	return p, err
}

// LoadPrice looks up the price for a model from the pricing table, falling back
// to defaults. Returns micro-credit per million tokens (no pre-division).
func LoadPrice(db *store.DB, model string) (Price, error) {
	p, err := scanPrice(db.SQL().QueryRow(`SELECT `+priceColumns+` FROM pricing WHERE model = ?`, model))
	if err == nil {
		return p, nil
	}

	defaults := DefaultPrices()
	if dp, ok := defaults[model]; ok {
		return dp, nil
	}
	// Fallback: any model sharing the family prefix.
	family := strings.Split(model, "-")[0]
	for key, dp := range defaults {
		if strings.HasPrefix(key, family) {
			return dp, nil
		}
	}
	// Absolute fallback: sonnet pricing.
	return Price{Model: model, InputPerMtok: 3_000_000, OutputPerMtok: 15_000_000, HoldMultiplier: 1.5}, nil
}

// ComputeCost calculates the micro-credit cost for a usage record. Prices are
// micro-credit per million tokens, so cost = tokens * rate / 1_000_000.
func ComputeCost(rec UsageRecord, price Price) int64 {
	input := float64(rec.Detail.InputTokens)
	output := float64(rec.Detail.OutputTokens)
	reasoning := float64(rec.Detail.ReasoningTokens)
	cacheRead := float64(rec.Detail.CacheReadTokens)
	cacheWrite := float64(rec.Detail.CacheCreationTokens)

	var micro float64
	if isCacheAdditive(rec.Provider) {
		// Anthropic: cache tokens are additive on top of input.
		micro = input*price.InputPerMtok +
			output*price.OutputPerMtok +
			reasoning*price.ReasoningPerMtok +
			cacheRead*price.CacheReadPerMtok +
			cacheWrite*price.CacheWritePerMtok
	} else {
		// Subset providers (OpenAI/Gemini): cache tokens already counted in input.
		micro = input*price.InputPerMtok +
			output*price.OutputPerMtok +
			reasoning*price.ReasoningPerMtok
	}
	return int64(micro / 1_000_000)
}

// isCacheAdditive reports whether cache tokens are additive (Anthropic) or a
// subset of input (OpenAI/Gemini).
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
	for _, p := range DefaultPrices() {
		if _, errExec := db.SQL().Exec(`
			INSERT INTO pricing (model, input_per_mtok, output_per_mtok, reasoning_per_mtok,
				cache_read_per_mtok, cache_write_per_mtok, hold_multiplier, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.Model, p.InputPerMtok, p.OutputPerMtok, p.ReasoningPerMtok,
			p.CacheReadPerMtok, p.CacheWritePerMtok, p.HoldMultiplier, store.Now()); errExec != nil {
			return fmt.Errorf("seed pricing %s: %w", p.Model, errExec)
		}
		log.Printf("[mkp] seeded pricing for %s", p.Model)
	}
	return nil
}

// UpdatePrice upserts one model's pricing row (admin management route).
func UpdatePrice(db *store.DB, p Price) error {
	_, err := db.SQL().Exec(`
		INSERT INTO pricing (model, input_per_mtok, output_per_mtok, reasoning_per_mtok,
			cache_read_per_mtok, cache_write_per_mtok, per_call_credit, hold_multiplier, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(model) DO UPDATE SET
			input_per_mtok=excluded.input_per_mtok, output_per_mtok=excluded.output_per_mtok,
			reasoning_per_mtok=excluded.reasoning_per_mtok, cache_read_per_mtok=excluded.cache_read_per_mtok,
			cache_write_per_mtok=excluded.cache_write_per_mtok, per_call_credit=excluded.per_call_credit,
			hold_multiplier=excluded.hold_multiplier, updated_at=excluded.updated_at`,
		p.Model, p.InputPerMtok, p.OutputPerMtok, p.ReasoningPerMtok,
		p.CacheReadPerMtok, p.CacheWritePerMtok, p.PerCallCredit, p.HoldMultiplier, store.Now())
	return err
}

// ListPrices returns all rows in the pricing table.
func ListPrices(db *store.DB) ([]Price, error) {
	rows, err := db.SQL().Query(`SELECT ` + priceColumns + ` FROM pricing ORDER BY model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Price
	for rows.Next() {
		p, errScan := scanPrice(rows)
		if errScan != nil {
			return nil, errScan
		}
		out = append(out, p)
	}
	if out == nil {
		out = []Price{}
	}
	return out, rows.Err()
}
