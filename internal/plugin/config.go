package plugin

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginConfig mirrors the YAML under plugins.configs.manager-key-pro.
// CPA merges enabled/priority automatically; the rest is plugin-owned.
type pluginConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Priority      int    `yaml:"priority"`
	DBPath        string `yaml:"db_path"`
	EncryptionKey string `yaml:"encryption_key"` // hex, or "env:NAME" to read from env
	LogMode       string `yaml:"log_mode"`       // full|standard|error_only
}

// parseConfigYAML decodes the raw YAML delivered by CPA in plugin.register.
func parseConfigYAML(raw string) (pluginConfig, error) {
	cfg := pluginConfig{
		DBPath:  "/root/cliproxyapi/mkp.db",
		LogMode: "standard",
	}
	// CPA base64-encodes the YAML before delivering it (see PoC observed.jsonl).
	data := []byte(raw)
	if decoded, errDec := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); errDec == nil && len(decoded) > 0 {
		data = decoded
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config yaml: %w (raw=%q)", err, raw[:min(80, len(raw))])
	}
	// Resolve env: prefix for the encryption key.
	if strings.HasPrefix(cfg.EncryptionKey, "env:") {
		name := strings.TrimPrefix(cfg.EncryptionKey, "env:")
		val := os.Getenv(name)
		if val == "" {
			return cfg, fmt.Errorf("encryption_key env %q is empty", name)
		}
		cfg.EncryptionKey = val
	}
	if cfg.EncryptionKey == "" {
		// Temporary fallback so the plugin can boot while the admin has not set
		// encryption_key yet. Production deployments MUST set encryption_key
		// (hex 64 chars or env:NAME). Without a stable key, Reveal will fail after
		// a restart if this fallback changes.
		cfg.EncryptionKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		// Do not fail boot; just use the fallback.
	}
	return cfg, nil
}
