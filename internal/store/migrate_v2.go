package store

import "fmt"

// migrateV2 upgrades schema v1 -> v2 (2026-08-19):
//   - keys/packages: plan_type (windowed|lifetime) + window_hours (custom quota
//     windows like the 5h / 7d / 10d presets; overrides quota_scope length)
//   - key_account_bindings: per-key upstream credential binding with share %
//   - request_logs: standard-mode rows carry full accounting fields so admin and
//     users can read what happened without joining raw JSON
func (d *DB) migrateV2() error {
	stmts := []string{
		`ALTER TABLE keys ADD COLUMN plan_type TEXT NOT NULL DEFAULT 'lifetime'`,
		`ALTER TABLE keys ADD COLUMN window_hours INTEGER`,
		`ALTER TABLE packages ADD COLUMN plan_type TEXT NOT NULL DEFAULT 'lifetime'`,
		`ALTER TABLE packages ADD COLUMN window_hours INTEGER`,
		`CREATE TABLE IF NOT EXISTS key_account_bindings (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			key_id       TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
			account_ref  TEXT NOT NULL,
			account_type TEXT NOT NULL DEFAULT '',
			share_percent INTEGER NOT NULL DEFAULT 100,
			priority     INTEGER NOT NULL DEFAULT 0,
			enabled      INTEGER NOT NULL DEFAULT 1,
			created_at   INTEGER NOT NULL,
			UNIQUE(key_id, account_ref)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bindings_key ON key_account_bindings(key_id, enabled)`,
		`ALTER TABLE request_logs ADD COLUMN model TEXT`,
		`ALTER TABLE request_logs ADD COLUMN alias TEXT`,
		`ALTER TABLE request_logs ADD COLUMN input_tokens INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE request_logs ADD COLUMN output_tokens INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE request_logs ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE request_logs ADD COLUMN cache_creation_tokens INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE request_logs ADD COLUMN cost INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE request_logs ADD COLUMN source TEXT`,
		`ALTER TABLE request_logs ADD COLUMN status TEXT`,
		`ALTER TABLE request_logs ADD COLUMN upstream_account TEXT`,
		`ALTER TABLE request_logs ADD COLUMN alias_model TEXT`,
		// Backfill plan_type from quota_scope.
		`UPDATE keys SET plan_type = 'windowed'
			WHERE quota_scope IN ('hour','day','week','month') OR window_hours IS NOT NULL`,
		`UPDATE packages SET plan_type = 'windowed'
			WHERE quota_scope IN ('hour','day','week','month') OR window_hours IS NOT NULL`,
		`UPDATE schema_meta SET version = 2 WHERE id = 1`,
	}
	for _, stmt := range stmts {
		if _, errExec := d.sql.Exec(stmt); errExec != nil {
			// ALTER TABLE ADD COLUMN fails with "duplicate column" when v2 was
			// already partly applied — treat that as done and continue.
			if isDuplicateColumn(errExec) {
				continue
			}
			return fmt.Errorf("migrate v2 (%s): %w", firstWords(stmt), errExec)
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "duplicate column name") || contains(msg, "already exists")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func firstWords(s string) string {
	out := make([]byte, 0, 48)
	words := 0
	for i := 0; i < len(s) && words < 5; i++ {
		c := s[i]
		if c == ' ' || c == '(' {
			words++
			if words == 5 {
				break
			}
		}
		out = append(out, c)
	}
	return string(out)
}
