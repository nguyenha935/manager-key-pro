package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Settings keys.
const (
	SettingFXMode             = "fx_mode"               // manual | auto
	SettingVNDPerUSD          = "vnd_per_usd"           // string float
	SettingReferralMode       = "referral_mode"         // percent | fixed
	SettingReferralTiers      = "referral_tiers"        // JSON array
	SettingReferralFixed      = "referral_fixed_credit" // string int64 (micro)
	SettingReferralQualify    = "referral_qualify_recharge"
	SettingGlobalLogMode      = "log_mode_global"
	SettingFullRetentionHours = "full_log_retention_hours"
	SettingBackupDir          = "backup_dir"
	SettingBackupWarnDays     = "backup_warn_days"
)

type SettingsRepo struct{ db *DB }

func (d *DB) Settings() *SettingsRepo { return &SettingsRepo{db: d} }

// InitDefaults inserts defaults for any missing keys (idempotent).
func (r *SettingsRepo) InitDefaults() error {
	defaults := map[string]string{
		SettingFXMode:             "manual",
		SettingVNDPerUSD:          "25000",
		SettingReferralMode:       "percent",
		SettingReferralTiers:      "[10,3,1]",
		SettingReferralFixed:      "1000000",
		SettingReferralQualify:    "10000000",
		SettingGlobalLogMode:      "standard",
		SettingFullRetentionHours: "24",
		SettingBackupDir:          "",
		SettingBackupWarnDays:     "7",
	}
	tx, err := r.db.sql.Begin()
	if err != nil {
		return fmt.Errorf("begin settings tx: %w", err)
	}
	defer tx.Rollback()
	for k, v := range defaults {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, k, v); err != nil {
			return fmt.Errorf("init setting %s: %w", k, err)
		}
	}
	return tx.Commit()
}

func (r *SettingsRepo) Get(key string) string {
	var v string
	if err := r.db.sql.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return ""
	}
	return v
}

func (r *SettingsRepo) GetInt(key string, def int64) int64 {
	v := strings.TrimSpace(r.Get(key))
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func (r *SettingsRepo) Set(key, value string) error {
	if _, err := r.db.sql.Exec(
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value); err != nil {
		return fmt.Errorf("set setting %s: %w", key, err)
	}
	return nil
}

func (r *SettingsRepo) SetInt(key string, v int64) error {
	return r.Set(key, strconv.FormatInt(v, 10))
}

func (r *SettingsRepo) GetJSON(key string, dest any) bool {
	v := strings.TrimSpace(r.Get(key))
	if v == "" {
		return false
	}
	return json.Unmarshal([]byte(v), dest) == nil
}

func (r *SettingsRepo) SetJSON(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return r.Set(key, string(raw))
}

func (r *SettingsRepo) All() (map[string]string, error) {
	rows, err := r.db.sql.Query(`SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("query settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if errScan := rows.Scan(&k, &v); errScan != nil {
			return nil, errScan
		}
		out[k] = v
	}
	return out, rows.Err()
}
