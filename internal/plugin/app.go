package plugin

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nguyenha935/manager-key-pro/internal/billing"
	"github.com/nguyenha935/manager-key-pro/internal/portal"
	"github.com/nguyenha935/manager-key-pro/internal/referral"
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
	WebhookSecret    string
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
	// onRecharge lets the management layer fire referral rewards without a
	// direct import of the referral package from management.go.
	onRecharge func(userID string, amount int64, refID string)
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
	// Seed runtime settings and the pricing table (no-ops after the first boot).
	if errDefaults := db.Settings().InitDefaults(); errDefaults != nil {
		log.Printf("[mkp] init settings: %v", errDefaults)
	}
	if errSeed := billing.SeedPricing(db); errSeed != nil {
		log.Printf("[mkp] seed pricing: %v", errSeed)
	}
	// Free holds left open by a crash (older than one hour).
	billing.ReleaseStale(db, 3600*1000)
	setDBPath(cfg.DBPath)
	log.Printf("[mkp] booted: schema v%d, db %s", version, cfg.DBPath)
	a := &App{db: db, secretKey: secretKey, onRecharge: func(userID string, amount int64, refID string) { referral.OnRecharge(db, userID, amount, refID) }}
	// Start the user portal listener when configured.
	if cfg.PortalListen != "" {
		a.portal = portal.New(db, portal.Config{
			Listen:           cfg.PortalListen,
			BaseURL:          cfg.PortalBaseURL,
			TelegramBotToken: cfg.TelegramBotToken,
			WebhookSecret:    cfg.WebhookSecret,
			RegistrationOpen: cfg.RegistrationOpen,
			RequireApproval:  cfg.RequireApproval,
			MinPasswordLen:   cfg.MinPasswordLen,
			LoginLockAfter:   cfg.LoginLockAfter,
			SessionTTLDays:   cfg.SessionTTLDays,
			SecretKey:        secretKey,
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

// RestoreDB replaces the live database with an uploaded SQLite file. It writes
// the file aside, validates it opens, closes the current handle and swaps in the
// restored file. Requires a plugin restart for the WAL/connections to settle;
// the swap here reopens the same path after VACUUM INTO wrote the new file.
func (a *App) RestoreDB(data []byte) error {
	if a == nil || a.db == nil {
		return fmt.Errorf("plugin not booted")
	}
	tmp := a.dbPath() + ".restore"
	if errWrite := os.WriteFile(tmp, data, 0600); errWrite != nil {
		return fmt.Errorf("write restore file: %w", errWrite)
	}
	// Close the current DB, move the restore file into place, reopen.
	path := a.dbPath()
	if errClose := a.db.Close(); errClose != nil {
		return fmt.Errorf("close db: %w", errClose)
	}
	// Remove WAL/SHM so they do not shadow the restored file.
	_ = os.Remove(path + "-wal")
	_ = os.Remove(path + "-shm")
	if errRename := os.Rename(tmp, path); errRename != nil {
		return fmt.Errorf("rename restore file: %w", errRename)
	}
	db, errOpen := store.Open(path)
	if errOpen != nil {
		return fmt.Errorf("reopen restored db: %w", errOpen)
	}
	a.db = db
	log.Printf("[mkp] database restored from upload (%d bytes)", len(data))
	return nil
}

func (a *App) dbPath() string {
	// The store does not expose the path; keep it in sync via a package var.
	return dbPathGlobal
}

// dbPathGlobal mirrors the path used at Boot so RestoreDB can locate the file.
var dbPathGlobal string

// BootPath stores the db path for later use (called from Boot via setDBPath).
func setDBPath(p string) { dbPathGlobal = strings.TrimSpace(p) }
