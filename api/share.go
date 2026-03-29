package api

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/i574789/otternetstat/network"
)

type shareEntry struct {
	snap      network.Snapshot
	expiresAt time.Time
}

// ShareStore holds short-lived read-only snapshot tokens.
type ShareStore struct {
	mu      sync.Mutex
	entries map[string]shareEntry
}

func NewShareStore() *ShareStore {
	s := &ShareStore{entries: make(map[string]shareEntry)}
	go s.reapLoop()
	return s
}

// Create stores a snapshot and returns an 8-byte hex token valid for 1 hour.
func (s *ShareStore) Create(snap network.Snapshot) string {
	b := make([]byte, 8)
	rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.entries[token] = shareEntry{snap: snap, expiresAt: time.Now().Add(time.Hour)}
	s.mu.Unlock()
	return token
}

// Get retrieves a snapshot by token. Returns false if not found or expired.
func (s *ShareStore) Get(token string) (network.Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[token]
	if !ok || time.Now().After(e.expiresAt) {
		delete(s.entries, token)
		return network.Snapshot{}, false
	}
	return e.snap, true
}

func (s *ShareStore) reapLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for tok, e := range s.entries {
			if now.After(e.expiresAt) {
				delete(s.entries, tok)
			}
		}
		s.mu.Unlock()
	}
}
