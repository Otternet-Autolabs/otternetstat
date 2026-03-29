package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

type challengeEntry struct {
	verified  bool
	expiresAt time.Time
}

// ChallengeStore issues single-use nonces for LAN proof-of-locality.
// A nonce is issued via the public endpoint and verified by hitting
// the LAN-only listener, which is unreachable from outside the LAN.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]*challengeEntry
}

func NewChallengeStore() *ChallengeStore {
	s := &ChallengeStore{entries: make(map[string]*challengeEntry)}
	go s.reapLoop()
	return s
}

// Issue creates a 16-byte hex nonce with a 30-second TTL.
func (s *ChallengeStore) Issue() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	nonce := hex.EncodeToString(b)
	s.mu.Lock()
	s.entries[nonce] = &challengeEntry{expiresAt: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return nonce
}

// Verify marks a nonce as verified. Returns false if not found or expired.
func (s *ChallengeStore) Verify(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[nonce]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.entries, nonce)
		return false
	}
	e.verified = true
	return true
}

// Status returns "pending", "verified", or "expired".
func (s *ChallengeStore) Status(nonce string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[nonce]
	if !ok {
		return "expired"
	}
	if time.Now().After(e.expiresAt) {
		delete(s.entries, nonce)
		return "expired"
	}
	if e.verified {
		return "verified"
	}
	return "pending"
}

func (s *ChallengeStore) reapLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for nonce, e := range s.entries {
			if now.After(e.expiresAt) {
				delete(s.entries, nonce)
			}
		}
		s.mu.Unlock()
	}
}

// newSessionToken generates a signed session cookie value: "<token>.<hmac>".
// The HMAC is SHA256 of the token keyed with secret, encoded as hex.
func newSessionToken(secret []byte) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	sig := hex.EncodeToString(mac.Sum(nil))
	return token + "." + sig, nil
}

// validSessionCookie verifies a signed cookie value produced by newSessionToken.
func validSessionCookie(value string, secret []byte) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}
