package billing

import (
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// WindowHours returns the length of one quota period in hours for the key's
// scope. windowHours (custom windows like 5h / 10d presets) overrides the
// standard scope mapping.
func WindowHours(scope string, windowHours int64) int64 {
	if windowHours > 0 {
		return windowHours
	}
	switch scope {
	case "hour":
		return 1
	case "day":
		return 24
	case "week":
		return 168
	case "month":
		return 24 * 30
	default: // lifetime
		return 0
	}
}

// EnsurePeriod initializes or resets the key's quota period when the scope is
// cyclic (windowed). Call before any hold/charge. Mutates the passed key to
// the refreshed state on reset.
func EnsurePeriod(db *store.DB, key *store.Key) error {
	if key.QuotaScope == "lifetime" || key.QuotaKind == "" {
		return nil
	}
	hours := WindowHours(key.QuotaScope, key.WindowHours)
	if hours <= 0 {
		return nil
	}
	now := store.Now()
	if key.PeriodStart <= 0 || key.PeriodEnd <= 0 || now >= key.PeriodEnd {
		start := now
		end := now + hours*3600*1000
		if errReset := db.Keys().ResetPeriod(key.ID, start, end); errReset != nil {
			return errReset
		}
		key.PeriodStart = start
		key.PeriodEnd = end
		key.QuotaUsed = 0
	}
	return nil
}
