package auth

import (
	"sync"
	"time"
)

type StateMetadata struct {
	SessionID string
	IP        string
	UserAgent string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type MemoryStateStorage struct {
	states map[string]StateMetadata
	mu     sync.RWMutex
}

func NewMemoryStateStorage() *MemoryStateStorage {
	return &MemoryStateStorage{
		states: make(map[string]StateMetadata),
	}
}

func (s *MemoryStateStorage) Save(state string, meta StateMetadata) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.states[state] = meta
}

func (s *MemoryStateStorage) Get(state string) (StateMetadata, bool) {
	s.mu.RLock()
	meta, ok := s.states[state]
	s.mu.RUnlock()

	if !ok {
		return StateMetadata{}, false
	}

	if time.Now().After(meta.ExpiresAt) {
		s.Delete(state)
		return StateMetadata{}, false
	}

	return meta, true
}

func (s *MemoryStateStorage) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, state)
}

func (s *MemoryStateStorage) CleanupExpired() {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for state, meta := range s.states {
		if now.After(meta.ExpiresAt) {
			delete(s.states, state)
		}
	}
}

func (s *MemoryStateStorage) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			s.CleanupExpired()
		}
	}()
}
