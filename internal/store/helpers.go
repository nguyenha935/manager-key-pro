package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// newID returns a prefixed, URL-safe identifier: "usr_J4K2M9...".
func newID(prefix string) string {
	buf := make([]byte, 10)
	if _, errRand := rand.Read(buf); errRand != nil {
		// crypto/rand failing means the system is broken; a time-based fallback
		// would silently weaken uniqueness, so panic loudly during startup paths.
		panic(fmt.Sprintf("crypto/rand unavailable: %v", errRand))
	}
	return prefix + "_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullIfZero(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

// isUniqueViolation reports whether err is a UNIQUE/PRIMARY KEY conflict.
// modernc.org/sqlite reports these as text, so match on the message.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint failed") ||
		strings.Contains(msg, "constraint failed: unique")
}

// requireOneRow turns "updated nothing" into ErrNotFound so callers can react.
func requireOneRow(result sql.Result) error {
	affected, errRows := result.RowsAffected()
	if errRows != nil {
		return fmt.Errorf("rows affected: %w", errRows)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// encodeJSONList stores a string list as a JSON array; empty means "no restriction".
func encodeJSONList(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	raw, errMarshal := json.Marshal(values)
	if errMarshal != nil {
		return "[]"
	}
	return string(raw)
}

// decodeJSONList reads a JSON array column back into a slice.
func decodeJSONList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	var values []string
	if errUnmarshal := json.Unmarshal([]byte(raw), &values); errUnmarshal != nil {
		return nil
	}
	return values
}

// IsNotFound reports whether err came from a missing row.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
