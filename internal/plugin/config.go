package plugin

import (
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
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, fmt.Errorf("parse config yaml: %w", err)
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
		return cfg, fmt.Errorf("encryption_key is required")
	}
	return cfg, nil
}
