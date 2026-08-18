package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// Errors callers are expected to branch on.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
	// ErrInsufficientBalance means a prepaid wallet cannot cover the amount.
	ErrInsufficientBalance = errors.New("insufficient balance")
)

// Ledger reasons. Kept as constants so a typo cannot slip past the CHECK constraint.
const (
	ReasonRecharge      = "recharge"
	ReasonUsage         = "usage"
	ReasonPurchase      = "purchase"
	ReasonRenew         = "renew"
	ReasonRefund        = "refund"
	ReasonOverflow      = "overflow"
	ReasonReferralBonus = "referral_bonus"
	ReasonAdjust        = "adjust"
	ReasonHold          = "hold"
)

// User mirrors one row of the users table. Wallet lives here, not on the key.
type User struct {
	ID           string
	Username     string
	PasswordHash string // empty when the account is Telegram-only
	TelegramID   string // empty when the account is password-only
	Role         string
	Status       string
	Balance      int64 // micro-credit
	WalletMode   string
	CreditLimit  int64
	ReferralCode string
	ReferredBy   string
	FailedLogins int
	LockedUntil  int64
	CreatedAt    int64
	LastLoginAt  int64
}

// IsAdmin reports whether the user may use admin-only operations.
func (u User) IsAdmin() bool { return u.Role == "admin" }

// CanSpend reports whether the wallet can still cover cost. Postpaid accounts may
// go negative down to their credit limit; prepaid accounts may not go below zero.
func (u User) CanSpend(cost int64) bool {
	if u.WalletMode == "postpaid" {
		return u.Balance-cost >= -u.CreditLimit
	}
	return u.Balance-cost >= 0
}

// UsersRepo reads and writes user rows.
type UsersRepo struct{ db *DB }

// Users returns the user repository.
func (d *DB) Users() *UsersRepo { return &UsersRepo{db: d} }

const userColumns = `id, username, COALESCE(password_hash,''), COALESCE(telegram_id,''),
	role, status, balance, wallet_mode, credit_limit, referral_code,
	COALESCE(referred_by,''), failed_logins, COALESCE(locked_until,0),
	created_at, COALESCE(last_login_at,0)`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	errScan := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TelegramID,
		&u.Role, &u.Status, &u.Balance, &u.WalletMode, &u.CreditLimit, &u.ReferralCode,
		&u.ReferredBy, &u.FailedLogins, &u.LockedUntil, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(errScan, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if errScan != nil {
		return User{}, fmt.Errorf("scan user: %w", errScan)
	}
	return u, nil
}

// Create inserts a user. Pass an empty passwordHash for Telegram-only accounts and
// an empty telegramID for password-only accounts.
func (r *UsersRepo) Create(username, passwordHash, telegramID, role string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username is required")
	}
	if role == "" {
		role = "user"
	}
	code, errCode := newReferralCode()
	if errCode != nil {
		return User{}, errCode
	}
	id := newID("usr")
	now := Now()
	_, errExec := r.db.sql.Exec(`
		INSERT INTO users (id, username, password_hash, telegram_id, role, status,
			balance, wallet_mode, credit_limit, referral_code, failed_logins, created_at)
		VALUES (?, ?, ?, ?, ?, 'active', 0, 'prepaid', 0, ?, 0, ?)`,
		id, username, nullIfEmpty(passwordHash), nullIfEmpty(telegramID), role, code, now)
	if errExec != nil {
		if isUniqueViolation(errExec) {
			return User{}, ErrDuplicate
		}
		return User{}, fmt.Errorf("insert user: %w", errExec)
	}
	return r.ByID(id)
}

// ByID loads one user.
func (r *UsersRepo) ByID(id string) (User, error) {
	return scanUser(r.db.sql.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// ByUsername loads a user for password login.
func (r *UsersRepo) ByUsername(username string) (User, error) {
	return scanUser(r.db.sql.QueryRow(`SELECT `+userColumns+` FROM users WHERE username = ?`, strings.TrimSpace(username)))
}

// ByTelegramID loads a user for Telegram login.
func (r *UsersRepo) ByTelegramID(telegramID string) (User, error) {
	return scanUser(r.db.sql.QueryRow(`SELECT `+userColumns+` FROM users WHERE telegram_id = ?`, telegramID))
}

// AdjustBalance moves the wallet by delta and appends a ledger row in one
// transaction. Negative delta spends; a prepaid wallet refuses to go below zero.
// Returns the balance after the move.
func (r *UsersRepo) AdjustBalance(userID string, delta int64, reason, refID, channel, keyID string) (int64, error) {
	var after int64
	errTx := r.db.Tx(func(tx *sql.Tx) error {
		var balance, limit int64
		var mode string
		errRow := tx.QueryRow(`SELECT balance, wallet_mode, credit_limit FROM users WHERE id = ?`, userID).
			Scan(&balance, &mode, &limit)
		if errors.Is(errRow, sql.ErrNoRows) {
			return ErrNotFound
		}
		if errRow != nil {
			return fmt.Errorf("read wallet: %w", errRow)
		}
		next := balance + delta
		floor := int64(0)
		if mode == "postpaid" {
			floor = -limit
		}
		if delta < 0 && next < floor {
			return ErrInsufficientBalance
		}
		if _, errUpdate := tx.Exec(`UPDATE users SET balance = ? WHERE id = ?`, next, userID); errUpdate != nil {
			return fmt.Errorf("update wallet: %w", errUpdate)
		}
		if _, errLedger := tx.Exec(`
			INSERT INTO credit_ledger (user_id, key_id, delta, reason, ref_id, channel, balance_after, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, nullIfEmpty(keyID), delta, reason, nullIfEmpty(refID), nullIfEmpty(channel), next, Now()); errLedger != nil {
			if isUniqueViolation(errLedger) {
				return ErrDuplicate // same telegram tx_id replayed
			}
			return fmt.Errorf("insert ledger: %w", errLedger)
		}
		after = next
		return nil
	})
	return after, errTx
}

// SetStatus enables, disables or bans an account.
func (r *UsersRepo) SetStatus(userID, status string) error {
	result, errExec := r.db.sql.Exec(`UPDATE users SET status = ? WHERE id = ?`, status, userID)
	if errExec != nil {
		return fmt.Errorf("set status: %w", errExec)
	}
	return requireOneRow(result)
}

// RecordLogin resets the lockout counter and stamps the login time.
func (r *UsersRepo) RecordLogin(userID string) error {
	_, errExec := r.db.sql.Exec(
		`UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE id = ?`,
		Now(), userID)
	if errExec != nil {
		return fmt.Errorf("record login: %w", errExec)
	}
	return nil
}

// RecordFailedLogin increments the counter and locks the account once it reaches
// lockAfter. Returns the locked-until timestamp, or 0 when not locked.
func (r *UsersRepo) RecordFailedLogin(userID string, lockAfter int, lockFor int64) (int64, error) {
	var lockedUntil int64
	errTx := r.db.Tx(func(tx *sql.Tx) error {
		var failed int
		if errRow := tx.QueryRow(`SELECT failed_logins FROM users WHERE id = ?`, userID).Scan(&failed); errRow != nil {
			if errors.Is(errRow, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("read failed logins: %w", errRow)
		}
		failed++
		if lockAfter > 0 && failed >= lockAfter {
			lockedUntil = Now() + lockFor
			failed = 0 // start a fresh window after the lock
		}
		_, errUpdate := tx.Exec(`UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?`,
			failed, nullIfZero(lockedUntil), userID)
		if errUpdate != nil {
			return fmt.Errorf("update failed logins: %w", errUpdate)
		}
		return nil
	})
	return lockedUntil, errTx
}

// LinkTelegram attaches a Telegram identity to an existing account.
func (r *UsersRepo) LinkTelegram(userID, telegramID string) error {
	result, errExec := r.db.sql.Exec(`UPDATE users SET telegram_id = ? WHERE id = ?`, telegramID, userID)
	if errExec != nil {
		if isUniqueViolation(errExec) {
			return ErrDuplicate
		}
		return fmt.Errorf("link telegram: %w", errExec)
	}
	return requireOneRow(result)
}

// SetPassword sets or replaces the password hash.
func (r *UsersRepo) SetPassword(userID, passwordHash string) error {
	result, errExec := r.db.sql.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, passwordHash, userID)
	if errExec != nil {
		return fmt.Errorf("set password: %w", errExec)
	}
	return requireOneRow(result)
}

// newReferralCode returns 8 uppercase base32 characters.
func newReferralCode() (string, error) {
	buf := make([]byte, 5) // 5 bytes -> exactly 8 base32 chars
	if _, errRand := rand.Read(buf); errRand != nil {
		return "", fmt.Errorf("generate referral code: %w", errRand)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}
