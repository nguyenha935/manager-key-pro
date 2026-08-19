// Package policy enforces the per-key restrictions declared in the keys table:
// allowed models/providers, IP allowlist and RPM. Gates run in
// request.intercept_before so a violation terminates the request with the
// documented error codes (design §9) instead of reaching an upstream.
package policy

import (
	"strings"
	"sync"
	"time"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Decision reports whether a request may proceed, and if not, the HTTP status
// and machine-readable error code to terminate with.
type Decision struct {
	Allowed       bool
	Status        int
	Code          string
	Message       string
	RetryAfterSec int
}

func allow() Decision { return Decision{Allowed: true} }

func deny(status int, code, msg string) Decision {
	return Decision{Allowed: false, Status: status, Code: code, Message: msg}
}

// CheckModel validates the requested model against the key allowlist. An empty
// allowlist permits every model. The requested alias and the resolved model are
// both checked so an alias cannot smuggle a blocked model.
func CheckModel(key store.Key, requestedModel, resolvedModel string) Decision {
	if len(key.AllowedModels) == 0 {
		return allow()
	}
	if matchList(key.AllowedModels, requestedModel) || matchList(key.AllowedModels, resolvedModel) {
		return allow()
	}
	return deny(403, "model_not_allowed",
		"model "+firstNonEmpty(requestedModel, resolvedModel)+" is not allowed for this key")
}

// CheckProvider validates the upstream provider against the key allowlist.
func CheckProvider(key store.Key, provider string) Decision {
	if len(key.AllowedProviders) == 0 || provider == "" {
		return allow()
	}
	if matchList(key.AllowedProviders, provider) {
		return allow()
	}
	return deny(403, "provider_not_allowed", "provider "+provider+" is not allowed for this key")
}

// CheckIP validates the client IP against the allowlist. Empty allowlist
// permits all. CIDR is not supported in v1 — exact match or wildcard suffix.
func CheckIP(key store.Key, ip string) Decision {
	if len(key.IPAllowlist) == 0 {
		return allow()
	}
	if ip != "" && matchList(key.IPAllowlist, ip) {
		return allow()
	}
	return deny(403, "ip_not_allowed", "client IP is not allowed for this key")
}

// matchList reports whether value matches any entry. Entries may end with "*"
// for prefix matching (e.g. "192.168.*", "claude-*").
func matchList(list []string, value string) bool {
	if value == "" {
		return false
	}
	value = strings.ToLower(strings.TrimSpace(value))
	for _, entry := range list {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if strings.HasSuffix(entry, "*") {
			if strings.HasPrefix(value, strings.TrimSuffix(entry, "*")) {
				return true
			}
			continue
		}
		if entry == value {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---- RPM limiter: in-memory sliding window per key ----

type rpmBucket struct {
	mu    sync.Mutex
	seen  map[string][]int64
	limit int
}

var rpm = &rpmBucket{seen: make(map[string][]int64)}

// CheckRPM allows at most key.RPM requests per sliding minute. When the limit
// is exceeded it reports 429 with a Retry-After hint. rpm <= 0 means unlimited.
func CheckRPM(key store.Key) Decision {
	if key.RPM <= 0 {
		return allow()
	}
	now := time.Now().UnixMilli()
	windowStart := now - 60_000

	rpm.mu.Lock()
	defer rpm.mu.Unlock()
	hits := rpm.seen[key.ID]
	kept := hits[:0]
	for _, ts := range hits {
		if ts >= windowStart {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= key.RPM {
		rpm.seen[key.ID] = kept
		retry := 1
		if earliest := kept[0]; earliest > windowStart {
			retry = int((earliest+60_000-now)/1000) + 1
		}
		return Decision{Allowed: false, Status: 429, Code: "rate_limit_exceeded",
			Message: "RPM limit exceeded for this key", RetryAfterSec: retry}
	}
	kept = append(kept, now)
	rpm.seen[key.ID] = kept
	return allow()
}

// CheckUserStatus blocks keys whose owner is not in good standing (design §9:
// 403 user_disabled for pending/disabled/banned).
func CheckUserStatus(user store.User) Decision {
	switch user.Status {
	case "active":
		return allow()
	case "pending":
		return deny(403, "user_disabled", "account is awaiting approval")
	case "disabled":
		return deny(403, "user_disabled", "account is disabled")
	case "banned":
		return deny(403, "user_disabled", "account is banned")
	default:
		return deny(403, "user_disabled", "account status is "+user.Status)
	}
}
