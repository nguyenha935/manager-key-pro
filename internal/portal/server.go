// Package portal runs the user-facing HTTP listener. It is separate from the
// CPA management routes because users POST (register, login, buy packages) and
// CPA management routes require the management key.
package portal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nguyenha935/manager-key-pro/internal/store"
	"golang.org/x/crypto/argon2"
)

// Config bundles the portal runtime settings.
type Config struct {
	Listen           string // e.g. "127.0.0.1:8788"
	BaseURL          string // e.g. "https://key.nguyenthanhha.com"
	TelegramBotToken string
	RegistrationOpen bool
	RequireApproval  bool
	MinPasswordLen   int
	LoginLockAfter   int
	SessionTTLDays   int
}

// Server owns the listener, DB handle, and in-memory session map.
type Server struct {
	db       *store.DB
	cfg      Config
	srv      *http.Server
	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
}

// New creates the portal server.
func New(db *store.DB, cfg Config) *Server {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8788"
	}
	if cfg.MinPasswordLen <= 0 {
		cfg.MinPasswordLen = 8
	}
	if cfg.LoginLockAfter <= 0 {
		cfg.LoginLockAfter = 5
	}
	if cfg.SessionTTLDays <= 0 {
		cfg.SessionTTLDays = 14
	}
	return &Server{
		db:       db,
		cfg:      cfg,
		sessions: make(map[string]*session),
	}
}

// Start begins listening. Non-blocking; errors are logged, not returned.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("GET /me/keys", s.handleMyKeys)
	mux.HandleFunc("GET /me/wallet", s.handleMyWallet)
	mux.HandleFunc("GET /me/referrals", s.handleMyReferrals)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"manager-key-pro-portal"}`))
	})

	s.srv = &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("[mkp-portal] listening on %s", s.cfg.Listen)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[mkp-portal] listener error: %v", err)
		}
	}()
}

// Stop shuts down the listener gracefully.
func (s *Server) Stop() {
	if s.srv != nil {
		s.srv.Close()
	}
}

// --- Auth handlers ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.RegistrationOpen {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "registration_closed"})
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
		return
	}
	if len(in.Password) < s.cfg.MinPasswordLen {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password too short"})
		return
	}
	// Hash password with argon2id.
	hash := hashPassword(in.Password)
	u, err := s.db.Users().Create(in.Username, hash, "", "user")
	if err != nil {
		if err == store.ErrDuplicate {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "username taken"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if s.cfg.RequireApproval {
		// Set status to pending.
		s.db.Users().SetStatus(u.ID, "pending")
		writeJSON(w, http.StatusCreated, map[string]any{
			"id": u.ID, "username": u.Username, "status": "pending",
			"message": "Account created. Waiting for admin approval.",
		})
		return
	}
	// Auto-approve: create session.
	token := s.createSession(u.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": u.ID, "username": u.Username, "status": u.Status,
		"referral_code": u.ReferralCode, "session_token": token,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	u, err := s.db.Users().ByUsername(in.Username)
	if err != nil {
		if store.IsNotFound(err) {
			// Do not reveal whether username exists.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Check lockout.
	if u.LockedUntil > 0 && store.Now() < u.LockedUntil {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "account locked"})
		return
	}
	// Check password.
	if !verifyPassword(u.PasswordHash, in.Password) {
		// Record failed login.
		lockedUntil, _ := s.db.Users().RecordFailedLogin(u.ID, s.cfg.LoginLockAfter, 15*60*1000)
		if lockedUntil > 0 {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "account locked"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if u.Status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account not active", "status": u.Status})
		return
	}
	s.db.Users().RecordLogin(u.ID)
	token := s.createSession(u.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role,
		"referral_code": u.ReferralCode, "session_token": token,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// --- Session management ---

func (s *Server) createSession(userID string) string {
	// Generate 32 random bytes for the token.
	buf := make([]byte, 32)
	rand.Read(buf)
	token := hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(sum[:])

	expires := time.Now().Add(time.Duration(s.cfg.SessionTTLDays) * 24 * time.Hour)
	s.mu.Lock()
	s.sessions[tokenHash] = &session{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: expires,
	}
	s.mu.Unlock()
	return token
}

func (s *Server) getSession(r *http.Request) (*session, bool) {
	token := extractToken(r)
	if token == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(sum[:])
	s.mu.RLock()
	sess, ok := s.sessions[tokenHash]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, tokenHash)
		s.mu.Unlock()
		return nil, false
	}
	return sess, true
}

func extractToken(r *http.Request) string {
	// Try Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	// Try cookie.
	cookie, err := r.Cookie("mkp_session")
	if err == nil {
		return cookie.Value
	}
	return ""
}

// --- Password hashing with argon2id ---

func hashPassword(password string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		hex.EncodeToString(salt), hex.EncodeToString(hash))
}

func verifyPassword(stored, password string) bool {
	if stored == "" {
		return false
	}
	// Parse stored hash: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	parts := strings.Split(stored, "$")
	if len(parts) != 6 {
		return false
	}
	saltHex := parts[4]
	expectedHashHex := parts[5]
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	expectedHash, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return false
	}
	actualHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	if len(actualHash) != len(expectedHash) {
		return false
	}
	for i := range actualHash {
		if actualHash[i] != expectedHash[i] {
			return false
		}
	}
	return true
}
