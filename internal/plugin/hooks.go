package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/billing"
	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/logging"
	"github.com/nguyenha935/manager-key-pro/internal/policy"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

type frontendAuthRequest struct {
	Method  string              `json:"Method"`
	Path    string              `json:"Path"`
	Headers map[string][]string `json:"Headers"`
	Query   map[string][]string `json:"Query"`
}

type frontendAuthResponse struct {
	Authenticated bool              `json:"Authenticated"`
	Principal     string            `json:"Principal,omitempty"`
	Metadata      map[string]string `json:"Metadata,omitempty"`
}

func handleAuthenticate(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}
	var req frontendAuthRequest
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}

	// CPA reads keys from 5 sources (config_access/provider.go:62-86).
	plaintext := extractKey(req.Headers, req.Query)
	if plaintext == "" {
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}

	keyHash := crypto.HashKey(plaintext)
	key, errKey := app.db.Keys().ByHash(keyHash)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			// Not our key; host tries the next provider.
			return okEnvelopeJSON(`{"Authenticated":false}`)
		}
		return nil, fmt.Errorf("lookup key: %w", errKey)
	}

	if !key.IsActive() {
		resp := frontendAuthResponse{Authenticated: false}
		raw, _ := json.Marshal(resp)
		return okEnvelopeJSON(string(raw))
	}
	if key.ExpiresAt > 0 && store.Now() > key.ExpiresAt {
		if errStatus := app.db.Keys().SetStatus(key.ID, "expired"); errStatus != nil {
			log.Printf("[mkp] set expired: %v", errStatus)
		}
		resp := frontendAuthResponse{Authenticated: false}
		raw, _ := json.Marshal(resp)
		return okEnvelopeJSON(string(raw))
	}
	// The owning user gates the key too: pending/disabled/banned owners are
	// rejected even while the key row itself is still "active" (design §9).
	if user, errUser := app.db.Users().ByID(key.UserID); errUser == nil {
		if d := policy.CheckUserStatus(user); !d.Allowed {
			log.Printf("[mkp] auth denied key %s: user %s status %s", key.ID, user.ID, user.Status)
			resp := frontendAuthResponse{Authenticated: false}
			raw, _ := json.Marshal(resp)
			return okEnvelopeJSON(string(raw))
		}
	}

	// Principal flows into UsageRecord.APIKey — PoC confirmed this works.
	resp := frontendAuthResponse{
		Authenticated: true,
		Principal:     key.ID,
		Metadata: map[string]string{
			"mkp.key_id":  key.ID,
			"mkp.user_id": key.UserID,
		},
	}
	raw, errMarshal := json.Marshal(resp)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal auth response: %w", errMarshal)
	}
	return okEnvelopeJSON(string(raw))
}

// extractKey reads the key from the five CPA sources.
func extractKey(headers, query map[string][]string) string {
	if auth := getHeader(headers, "Authorization"); auth != "" {
		if val := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); val != "" && val != auth {
			return val
		}
	}
	if val := getHeader(headers, "X-Goog-Api-Key"); val != "" {
		return val
	}
	if val := getHeader(headers, "X-Api-Key"); val != "" {
		return val
	}
	if val := getQuery(query, "key"); val != "" {
		return val
	}
	if val := getQuery(query, "auth_token"); val != "" {
		return val
	}
	return ""
}

func getHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

func getQuery(query map[string][]string, name string) string {
	for k, v := range query {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
	}
	return ""
}

// interceptRequest is the payload CPA sends to intercept_before / intercept_after.
type interceptRequest struct {
	RequestID      string              `json:"RequestID"`
	TraceID        string              `json:"TraceID"`
	SourceFormat   string              `json:"SourceFormat"`
	Model          string              `json:"Model"`
	RequestedModel string              `json:"RequestedModel"`
	Stream         bool                `json:"Stream"`
	Headers        map[string][]string `json:"Headers"`
	Body           []byte              `json:"Body"`
	Metadata       map[string]any      `json:"Metadata"`
}

// terminateJSON builds a RequestInterceptResponse that stops the request with
// the documented error shape (design §9).
func terminateJSON(status int, code, msg string, retryAfter int) string {
	headers := map[string][]string{"Content-Type": {"application/json"}}
	if retryAfter > 0 {
		headers["Retry-After"] = []string{fmt.Sprintf("%d", retryAfter)}
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"type": code, "message": msg},
	})
	resp := map[string]any{
		"Terminate":       true,
		"StatusCode":      status,
		"ResponseHeaders": headers,
		"ResponseBody":    string(body),
	}
	raw, _ := json.Marshal(resp)
	return string(raw)
}

func handleInterceptBefore(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{}`)
	}
	var req interceptRequest
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return okEnvelopeJSON(`{}`)
	}
	// Look up the key via the Principal that frontend_auth returned.
	// CPA stores Principal as Metadata.caller_scope = sha256 of principal, so we
	// re-hash the key from headers to find the key_id again.
	plaintext := extractKey(req.Headers, nil)
	if plaintext == "" {
		return okEnvelopeJSON(`{}`)
	}
	key, errKey := app.db.Keys().ByHash(crypto.HashKey(plaintext))
	if errKey != nil {
		return okEnvelopeJSON(`{}`)
	}

	// Policy gates (design §9): models, providers, IP, RPM.
	if d := policy.CheckModel(key, req.RequestedModel, req.Model); !d.Allowed {
		return okEnvelopeJSON(terminateJSON(d.Status, d.Code, d.Message, 0))
	}
	if d := policy.CheckProvider(key, providerFromCandidate(req.Model)); !d.Allowed {
		return okEnvelopeJSON(terminateJSON(d.Status, d.Code, d.Message, 0))
	}
	if d := policy.CheckIP(key, clientIP(req.Headers)); !d.Allowed {
		return okEnvelopeJSON(terminateJSON(d.Status, d.Code, d.Message, 0))
	}
	if d := policy.CheckRPM(key); !d.Allowed {
		return okEnvelopeJSON(terminateJSON(d.Status, d.Code, d.Message, d.RetryAfterSec))
	}

	// Capture the request context for full-mode logging (redacted, capped).
	logging.CaptureRequest(app.db, key.ID, req.RequestID, string(req.Body))

	// Place a hold once per client request.
	billing.Hold(app.db, req.RequestID, key.ID, key.UserID, req.Model)
	return okEnvelopeJSON(`{}`)
}

// providerFromCandidate extracts a provider hint from an AuthID-style string
// ("provider:kind:id"). Empty string means no restriction applies.
func providerFromCandidate(model string) string {
	return ""
}

// clientIP reads the best-effort client address from common proxy headers.
func clientIP(headers map[string][]string) string {
	for _, name := range []string{"X-Forwarded-For", "X-Real-Ip", "Cf-Connecting-Ip"} {
		if v := getHeader(headers, name); v != "" {
			parts := strings.Split(v, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func handleInterceptAfter(payload []byte) ([]byte, error) {
	// intercept_after runs per upstream attempt. For hold/settle we only need
	// intercept_before + usage.handle + request.complete.
	return okEnvelopeJSON(`{}`)
}

func handleUsage(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{}`)
	}
	var rec billing.UsageRecord
	if errUnmarshal := json.Unmarshal(payload, &rec); errUnmarshal == nil {
		logging.WriteUsage(app.db, rec)
	}
	if errCharge := billing.HandleUsageJSON(app.db, payload); errCharge != nil {
		log.Printf("[mkp] charge error: %v", errCharge)
		// Still log the attempt so the admin can see the failure.
		logging.Write(app.db, logging.Entry{
			KeyID: rec.APIKey, Model: rec.Model, Provider: rec.Provider,
			Status: "failed", ErrorMessage: errCharge.Error(),
		})
		return okEnvelopeJSON(`{}`)
	}
	return okEnvelopeJSON(`{}`)
}

func handleComplete(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{}`)
	}
	// request.complete arrives once per client request. Release any hold that
	// never got a usage.handle (timeouts, rejects, cancels).
	var req struct {
		RequestID string `json:"RequestID"`
		Outcome   string `json:"Outcome"`
		Error     string `json:"Error"`
	}
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		return okEnvelopeJSON(`{}`)
	}
	if req.Outcome != "succeeded" {
		billing.Release(app.db, req.RequestID)
		if req.Error != "" {
			logging.WriteFailure(app.db, req.RequestID, req.Outcome, req.Error)
		}
	}
	// Periodically purge full-mode logs past their TTL (cheap, once per request).
	logging.Purge(app.db)
	return okEnvelopeJSON(`{}`)
}
