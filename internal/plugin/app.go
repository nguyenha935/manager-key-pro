package plugin

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/billing"
	"github.com/nguyenha935/manager-key-pro/internal/crypto"
	"github.com/nguyenha935/manager-key-pro/internal/portal"
	"github.com/nguyenha935/manager-key-pro/internal/store"
)

// Config bundles the plugin's runtime settings.
type Config struct {
	DBPath    string
	SecretKey string // 64 hex chars = 32 bytes for AES-256
	// Portal settings.
	PortalListen     string
	PortalBaseURL    string
	TelegramBotToken string
	RegistrationOpen bool
	RequireApproval  bool
	MinPasswordLen   int
	LoginLockAfter   int
	SessionTTLDays   int
}

// App is the plugin's global state: DB handle + repos + config.
type App struct {
	db        *store.DB
	secretKey []byte
	portal    *portal.Server
}

// Boot opens the database and prepares the repositories.
func Boot(cfg Config) (*App, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("db_path is required")
	}
	db, errOpen := store.Open(cfg.DBPath)
	if errOpen != nil {
		return nil, fmt.Errorf("open db: %w", errOpen)
	}
	secretKey, errDecode := hex.DecodeString(cfg.SecretKey)
	if errDecode != nil || len(secretKey) != 32 {
		if errClose := db.Close(); errClose != nil {
			log.Printf("[mkp] close db after secret decode failure: %v", errClose)
		}
		return nil, fmt.Errorf("secret_key must be 64 hex chars (32 bytes)")
	}
	version, errVersion := db.SchemaVersion()
	if errVersion != nil {
		if errClose := db.Close(); errClose != nil {
			log.Printf("[mkp] close db after schema version failure: %v", errClose)
		}
		return nil, fmt.Errorf("schema version: %w", errVersion)
	}
	// Seed the pricing table on first boot (no-op if rows already exist).
	if errSeed := billing.SeedPricing(db); errSeed != nil {
		log.Printf("[mkp] seed pricing: %v", errSeed)
	}
	log.Printf("[mkp] booted: schema v%d, db %s", version, cfg.DBPath)
	a := &App{db: db, secretKey: secretKey}
	// Start the user portal listener when configured.
	if cfg.PortalListen != "" {
		a.portal = portal.New(db, portal.Config{
			Listen:           cfg.PortalListen,
			BaseURL:          cfg.PortalBaseURL,
			TelegramBotToken: cfg.TelegramBotToken,
			RegistrationOpen: cfg.RegistrationOpen,
			RequireApproval:  cfg.RequireApproval,
			MinPasswordLen:   cfg.MinPasswordLen,
			LoginLockAfter:   cfg.LoginLockAfter,
			SessionTTLDays:   cfg.SessionTTLDays,
		})
		a.portal.Start()
	}
	return a, nil
}

// Close releases the database handle.
func (a *App) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	if a.portal != nil {
		a.portal.Stop()
	}
	return a.db.Close()
}

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
	log.Printf("[mkp] handleAuthenticate called")
	if app == nil {
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}
	var req frontendAuthRequest
	if errUnmarshal := json.Unmarshal(payload, &req); errUnmarshal != nil {
		log.Printf("[mkp] auth unmarshal error: %v", errUnmarshal)
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}

	// CPA reads keys from 5 sources (config_access/provider.go:62-86).
	// §8 research confirmed all five arrive in Headers/Query; read them all.
	plaintext := extractKey(req.Headers, req.Query)
	hkeys := ""
	for k := range req.Headers {
		hkeys += k + " "
	}
	info := ""
	if len(plaintext) >= 10 {
		info = plaintext[:10] + "..."
	} else if plaintext != "" {
		info = plaintext + "..."
	} else {
		info = "(none)"
	}
	log.Printf("[mkp] handleAuthenticate called:0: %s", info)
	if plaintext == "" {
		return okEnvelopeJSON(`{"Authenticated":false}`)
	}

	keyHash := crypto.HashKey(plaintext)
	key, errKey := app.db.Keys().ByHash(keyHash)
	if errKey != nil {
		if store.IsNotFound(errKey) {
			// Not our key; host tries the next provider (e.g. cpa-key-policy).
			return okEnvelopeJSON(`{"Authenticated":false}`)
		}
		return nil, fmt.Errorf("lookup key: %w", errKey)
	}

	// Gate: check status, expiry, IP allowlist. Quota is checked later at billing.
	if !key.IsActive() {
		resp := frontendAuthResponse{Authenticated: false}
		raw, _ := json.Marshal(resp)
		return okEnvelopeJSON(string(raw))
	}
	if key.ExpiresAt > 0 && store.Now() > key.ExpiresAt {
		// Auto-mark expired so the user sees it in the dashboard.
		if errStatus := app.db.Keys().SetStatus(key.ID, "expired"); errStatus != nil {
			log.Printf("[mkp] set expired: %v", errStatus)
		}
		resp := frontendAuthResponse{Authenticated: false}
		raw, _ := json.Marshal(resp)
		return okEnvelopeJSON(string(raw))
	}

	// TODO: check IP allowlist when len(key.IPAllowlist) > 0.

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

// extractKey reads the key from the five CPA sources (§8 PoC confirmed all arrive).
func extractKey(headers, query map[string][]string) string {
	// 1. Authorization: Bearer <key>
	if auth := getHeader(headers, "Authorization"); auth != "" {
		if val := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")); val != "" && val != auth {
			return val
		}
	}
	// 2. X-Goog-Api-Key (Gemini clients)
	if val := getHeader(headers, "X-Goog-Api-Key"); val != "" {
		return val
	}
	// 3. X-Api-Key
	if val := getHeader(headers, "X-Api-Key"); val != "" {
		return val
	}
	// 4. ?key=...
	if val := getQuery(query, "key"); val != "" {
		return val
	}
	// 5. ?auth_token=...
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

func handleInterceptBefore(payload []byte) ([]byte, error) {
	// TODO: place hold here once per client request (§3b rule 1).
	// For v0.1, we skip hold and settle directly at usage.handle.
	return okEnvelopeJSON(`{}`)
}

func handleUsageStub(payload []byte) ([]byte, error) {
	// TODO: billing — charge key quota or wallet, apply 3 anti-duplicate rules.
	// For now, just acknowledge so CPA doesn't log errors.
	return okEnvelopeJSON(`{}`)
}

func handleComplete(payload []byte) ([]byte, error) {
	// request.complete arrives once per client request. Use it to release holds
	// that never got a usage.handle (e.g. timeout before upstream responds).
	// For v0.1, nothing to do yet.
	return okEnvelopeJSON(`{}`)
}

func handleUsage(payload []byte) ([]byte, error) {
	if app == nil {
		return okEnvelopeJSON(`{}`)
	}
	// Dump first 800 bytes of the payload once so we can verify wire format.
	if errCharge := billing.HandleUsageJSON(app.db, payload); errCharge != nil {
		log.Printf("[mkp] charge error: %v", errCharge)
		return okEnvelopeJSON(`{}`)
	}
	return okEnvelopeJSON(`{}`)
}

func handleInterceptAfter(payload []byte) ([]byte, error) {
	// intercept_after runs per upstream attempt. For v0.1, nothing to do.
	return okEnvelopeJSON(`{}`)
}
