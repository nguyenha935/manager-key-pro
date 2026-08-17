// Package crypto handles key generation, hashing for auth, and AES-256-GCM encryption
// for reveal. The plaintext key lives in memory only during Create and Reveal.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

// GenerateKey returns a plaintext key in CPA-compatible format: "sk-" + 45 base32
// chars. CPA accepts any string key (no format rules), but staying close to the
// native sk-ant-* pattern keeps portal UX consistent.
func GenerateKey() (string, error) {
	buf := make([]byte, 28) // 28 bytes -> 45 base32 chars (no padding)
	if _, errRand := io.ReadFull(rand.Reader, buf); errRand != nil {
		return "", fmt.Errorf("generate key: %w", errRand)
	}
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	return "sk-" + encoded, nil
}

// HashKey returns the sha256 hex digest used for lookups in keys.key_hash.
func HashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return fmt.Sprintf("%x", sum)
}

// Prefix extracts the display prefix from a plaintext key: "sk-abc...".
func Prefix(plaintext string) string {
	if len(plaintext) <= 10 {
		return plaintext
	}
	return plaintext[:10] + "…"
}

// EncryptKey wraps the plaintext key in AES-256-GCM with a random nonce. Returns
// (ciphertext, nonce, error). The secret must be exactly 32 bytes (AES-256).
func EncryptKey(plaintext string, secret []byte) ([]byte, []byte, error) {
	if len(secret) != 32 {
		return nil, nil, fmt.Errorf("secret must be 32 bytes, got %d", len(secret))
	}
	block, errCipher := aes.NewCipher(secret)
	if errCipher != nil {
		return nil, nil, fmt.Errorf("new cipher: %w", errCipher)
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return nil, nil, fmt.Errorf("new GCM: %w", errGCM)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, errRand := io.ReadFull(rand.Reader, nonce); errRand != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", errRand)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, nil
}

// DecryptKey unwraps the ciphertext back into plaintext. The secret must match the
// one used in EncryptKey.
func DecryptKey(ciphertext, nonce, secret []byte) (string, error) {
	if len(secret) != 32 {
		return "", fmt.Errorf("secret must be 32 bytes, got %d", len(secret))
	}
	block, errCipher := aes.NewCipher(secret)
	if errCipher != nil {
		return "", fmt.Errorf("new cipher: %w", errCipher)
	}
	gcm, errGCM := cipher.NewGCM(block)
	if errGCM != nil {
		return "", fmt.Errorf("new GCM: %w", errGCM)
	}
	plaintext, errOpen := gcm.Open(nil, nonce, ciphertext, nil)
	if errOpen != nil {
		return "", fmt.Errorf("decrypt: %w", errOpen)
	}
	return string(plaintext), nil
}
