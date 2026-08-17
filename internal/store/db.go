// Package store owns the SQLite database: schema, migrations and repositories.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, no CGO toolchain needed
)

//go:embed schema.sql
var schemaSQL string

// DB wraps the SQLite handle shared by every repository.
type DB struct {
	sql *sql.DB
}

// Open prepares the database file and applies the schema. It is safe to call on
// an existing database: every statement in schema.sql is IF NOT EXISTS.
func Open(path string) (*DB, error) {
	// _txlock=immediate makes write transactions take the lock upfront, which
	// avoids "database is locked" surprises when two requests settle at once.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_txlock=immediate", path)
	handle, errOpen := sql.Open("sqlite", dsn)
	if errOpen != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", path, errOpen)
	}
	// SQLite handles one writer at a time; keeping the pool small avoids lock churn.
	handle.SetMaxOpenConns(4)
	handle.SetMaxIdleConns(4)
	handle.SetConnMaxLifetime(time.Hour)

	db := &DB{sql: handle}
	if errMigrate := db.migrate(); errMigrate != nil {
		if errClose := handle.Close(); errClose != nil {
			return nil, fmt.Errorf("migrate: %w (and close: %v)", errMigrate, errClose)
		}
		return nil, errMigrate
	}
	return db, nil
}

func (d *DB) migrate() error {
	if _, errExec := d.sql.Exec(schemaSQL); errExec != nil {
		return fmt.Errorf("apply schema: %w", errExec)
	}
	return nil
}

// SchemaVersion reports the applied schema version.
func (d *DB) SchemaVersion() (int, error) {
	var version int
	errQuery := d.sql.QueryRow(`SELECT version FROM schema_meta WHERE id = 1`).Scan(&version)
	if errQuery != nil {
		return 0, fmt.Errorf("read schema version: %w", errQuery)
	}
	return version, nil
}

// SQL exposes the handle for repositories in this package.
func (d *DB) SQL() *sql.DB { return d.sql }

// Close releases the database handle.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// Tx runs fn inside a transaction, rolling back on error or panic. Money moves
// (wallet debit + ledger row + usage row) must always go through here so they
// cannot land half-written.
func (d *DB) Tx(fn func(tx *sql.Tx) error) (err error) {
	tx, errBegin := d.sql.Begin()
	if errBegin != nil {
		return fmt.Errorf("begin tx: %w", errBegin)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if errRollback := tx.Rollback(); errRollback != nil {
				err = fmt.Errorf("panic %v (rollback: %v)", recovered, errRollback)
				return
			}
			err = fmt.Errorf("panic during tx: %v", recovered)
		}
	}()
	if errFn := fn(tx); errFn != nil {
		if errRollback := tx.Rollback(); errRollback != nil {
			return fmt.Errorf("%w (rollback: %v)", errFn, errRollback)
		}
		return errFn
	}
	if errCommit := tx.Commit(); errCommit != nil {
		return fmt.Errorf("commit tx: %w", errCommit)
	}
	return nil
}

// Now returns the millisecond timestamp used across every table.
func Now() int64 { return time.Now().UnixMilli() }
