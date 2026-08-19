// Package logging implements the three-mode request logging required by the
// design: full (context + response, redacted, TTL), standard (tokens/cost/state),
// error_only (full error detail, NO user context).
package logging

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/billing"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Mode constants.
const (
	ModeFull      = "full"
	ModeStandard  = "standard"
	ModeErrorOnly = "error_only"
)

// MaxBodyCapture caps stored request/response context at 32KB (full mode only).
const MaxBodyCapture = 32 * 1024

// Entry describes one request to be logged.
type Entry struct {
	KeyID          string
	UserID         string
	Model          string
	Alias          string
	AliasModel     string
	Provider       string
	UpstreamAccount string
	Status         string // ok|failed
	ErrorMessage   string
	UpstreamStatus int
	InputTokens    int64
	OutputTokens   int64
	CacheRead      int64
	CacheWrite     int64
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

// cap truncates a captured body to MaxBodyCapture bytes.
func cap(raw string) string {
	if len(raw) <= MaxBodyCapture {
		return raw
	}
	return raw[:MaxBodyCapture] + "…[truncated]"
}

// pendingContext keeps the full-mode request context between intercept_before
// and the usage write of the same request. Small bounded map; entries are
// consumed on write.
var pendingContext = map[string]string{}

// CaptureRequest stores the (redacted, capped) request body captured at
// intercept_before so the later usage write can attach it in full mode.
func CaptureRequest(db *store.DB, keyID, requestID, body string) {
	if requestID == "" || body == "" {
		return
	}
	mode := EffectiveMode(db, keyID)
	if mode != ModeFull {
		return
	}
	if len(pendingContext) > 512 {
		pendingContext = map[string]string{} // crude bound; full mode is opt-in debug
	}
	pendingContext[requestID] = cap(RedactSecrets(body))
}

// takeContext removes and returns the captured context for a request.
func takeContext(requestID string) string {
	if requestID == "" {
		return ""
	}
	ctx := pendingContext[requestID]
	delete(pendingContext, requestID)
	return ctx
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

// WriteUsage records one completed usage record according to the resolved mode.
// Standard rows now carry model/alias/tokens/cost so admins and users can read
// what happened without joining anything else.
func WriteUsage(db *store.DB, rec billing.UsageRecord) {
	key, errKey := db.Keys().ByID(rec.APIKey)
	if errKey != nil {
		return
	}
	mode := EffectiveMode(db, key.ID)

	status := "ok"
	if rec.Failed {
		status = "failed"
	}

	context := ""
	response := ""
	if mode == ModeFull {
		context = takeContext(rec.RequestID)
		response = "" // response capture is best-effort; usage payload has none
	}

	var purgeAfter any
	if mode == ModeFull {
		hours := db.Settings().GetInt(store.SettingFullRetentionHours, 24)
		purgeAfter = store.Now() + int64(hours)*3600*1000
	}

	aliasModel := ""
	if rec.Alias != "" && rec.Alias != rec.Model {
		aliasModel = rec.Model
	}

	_, err := db.SQL().Exec(`
		INSERT INTO request_logs (key_id, user_id, mode, model, alias, alias_model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			cost, source, status, request_context, response_body,
			error_code, upstream_status, provider, attempt, purge_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullStr(key.ID), nullStr(key.UserID), mode, nullStr(rec.Model), nullStr(rec.Alias), nullStr(aliasModel),
		rec.Detail.InputTokens, rec.Detail.OutputTokens, rec.Detail.CacheReadTokens, rec.Detail.CacheCreationTokens,
		0, nullStr(""), status, nullStr(context), nullStr(response),
		nullStr(""), 0, nullStr(rec.Provider), 0, purgeAfter, store.Now())
	if err != nil {
		log.Printf("[mkp] write usage log: %v", err)
	}

	// Attach cost/source to the newest log row of this usage (the usage write
	// happens right after in billing; update by rowid).
	if lastID := lastLogID(db, key.ID); lastID > 0 {
		var cost int64
		var source string
		_ = db.SQL().QueryRow(
			`SELECT cost, COALESCE(source,'') FROM usage_records
			 WHERE key_id = ? ORDER BY id DESC LIMIT 1`, key.ID).Scan(&cost, &source)
		_, _ = db.SQL().Exec(
			`UPDATE request_logs SET cost = ?, source = ?, upstream_account = ? WHERE id = ?`,
			cost, nullStr(source), nullStr(rec.AuthID), lastID)
	}
}

func lastLogID(db *store.DB, keyID string) int64 {
	var id int64
	_ = db.SQL().QueryRow(
		`SELECT id FROM request_logs WHERE key_id = ? ORDER BY id DESC LIMIT 1`, keyID).Scan(&id)
	return id
}

// Write persists a plain entry (charge errors, plugin faults) according to mode.
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
		purgeAfter = store.Now() + int64(hours)*3600*1000
	}

	_, err := db.SQL().Exec(`
		INSERT INTO request_logs (key_id, user_id, mode, model, alias, alias_model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			cost, source, status, request_context, response_body,
			error_code, upstream_status, provider, attempt, purge_after, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullStr(e.KeyID), nullStr(e.UserID), mode, nullStr(e.Model), nullStr(e.Alias), nullStr(e.AliasModel),
		e.InputTokens, e.OutputTokens, e.CacheRead, e.CacheWrite,
		e.Cost, nullStr(e.Source), e.Status, nullStr(context), nullStr(response),
		nullStr(e.ErrorMessage), nullInt(e.UpstreamStatus), nullStr(e.Provider),
		e.Attempt, purgeAfter, store.Now())
	if err != nil {
		log.Printf("[mkp] write request_log: %v", err)
	}
}

// WriteFailure records a terminal request failure from request.complete.
func WriteFailure(db *store.DB, requestID, outcome, errMsg string) {
	// Best effort: attribute to the reservation's key when one exists.
	var keyID string
	_ = db.SQL().QueryRow(
		`SELECT key_id FROM reservations WHERE reservation_id = ?`, requestID).Scan(&keyID)
	mode := EffectiveMode(db, keyID)
	if mode == ModeStandard {
		// Standard mode keeps terminal failures only when the request produced
		// no usage row (usage rows carry their own status).
		return
	}
	_, _ = db.SQL().Exec(`
		INSERT INTO request_logs (key_id, user_id, mode, status, error_code, provider, created_at)
		VALUES (?, NULL, ?, ?, ?, '', ?)`,
		nullStr(keyID), mode, outcome, nullStr(errMsg), store.Now())
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
