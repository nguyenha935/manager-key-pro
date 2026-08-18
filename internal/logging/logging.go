// Package logging implements the three-mode request logging required by the
// design: full (context + response, redacted, TTL), standard (tokens/cost/state),
// error_only (full error detail, NO user context).
package logging

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Mode constants.
const (
	ModeFull      = "full"
	ModeStandard  = "standard"
	ModeErrorOnly = "error_only"
)

// Entry describes one request to be logged.
type Entry struct {
	KeyID          string
	UserID         string
	Model          string
	Provider       string
	Status         string // ok|failed
	ErrorMessage   string
	UpstreamStatus int
	InputTokens    int64
	OutputTokens   int64
	Cost           int64
	Source         string
	Attempt        int
	RequestContext string // raw context, only stored when mode=full
	ResponseBody   string // raw response, only stored when mode=full
}

// secrets redacted before storage.
var secretPatterns = []string{
	"authorization", "api-key", "apikey", "x-api-key", "x-goog-api-key",
	"cookie", "bearer",
}

// RedactSecrets removes values that look like secrets from a raw string.
func RedactSecrets(raw string) string {
	if raw == "" {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		redactMap(obj)
		out, _ := json.Marshal(obj)
		return string(out)
	}
	return raw
}

func redactMap(m map[string]any) {
	for k, v := range m {
		lk := strings.ToLower(k)
		for _, pat := range secretPatterns {
			if strings.Contains(lk, pat) {
				m[k] = "[REDACTED]"
				break
			}
		}
		if sub, ok := v.(map[string]any); ok {
			redactMap(sub)
		}
	}
}

// EffectiveMode resolves the mode for a key: per-key override wins, else global.
func EffectiveMode(db *store.DB, keyID string) string {
	if keyID != "" {
		var mode sql.NullString
		err := db.SQL().QueryRow(`SELECT log_mode FROM keys WHERE id = ?`, keyID).Scan(&mode)
		if err == nil && mode.Valid && mode.String != "" {
			return mode.String
		}
	}
	global := db.Settings().Get(store.SettingGlobalLogMode)
	if global == "" {
		return ModeStandard
	}
	return global
}

// Write persists one entry according to the resolved mode.
func Write(db *store.DB, e Entry) {
	mode := EffectiveMode(db, e.KeyID)
	if mode == ModeErrorOnly && e.Status == "ok" {
		return
	}

	context := ""
	response := ""
	if mode == ModeFull {
		context = RedactSecrets(e.RequestContext)
		response = RedactSecrets(e.ResponseBody)
	}

	var purgeAfter any
	if mode == ModeFull {
		hours := db.Settings().GetInt(store.SettingFullRetentionHours, 24)
		purgeAfter = store.Now() + hours*3600*1000
	}

	_, err := db.SQL().Exec(`
		INSERT INTO request_logs (key_id, user_id, mode, request_context, response_body,
			error_code, upstream_status, provider, attempt, purge_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullStr(e.KeyID), nullStr(e.UserID), mode, nullStr(context), nullStr(response),
		nullStr(e.ErrorMessage), nullInt(e.UpstreamStatus), nullStr(e.Provider),
		e.Attempt, purgeAfter, store.Now())
	if err != nil {
		log.Printf("[mkp] write request_log: %v", err)
	}
}

// Purge deletes full-mode rows past their TTL.
func Purge(db *store.DB) int {
	res, err := db.SQL().Exec(
		`DELETE FROM request_logs WHERE purge_after IS NOT NULL AND purge_after < ?`, store.Now())
	if err != nil {
		return 0
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Printf("[mkp] purged %d expired full-mode logs", n)
	}
	return int(n)
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
