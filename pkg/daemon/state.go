package daemon

import (
	"sync"
	"time"
)

// AuthState represents the authentication state for a cache key.
type AuthState string

const (
	StateValid           AuthState = "VALID"
	StateRefreshing      AuthState = "REFRESHING"
	StateNeedsLogin      AuthState = "NEEDS_LOGIN"
	StateLoginInProgress AuthState = "LOGIN_IN_PROGRESS"
)

// loginInProgressTTL is the maximum time a LOGIN_IN_PROGRESS state can persist
// before auto-reverting to NEEDS_LOGIN. Prevents stuck state if login process
// crashes without sending cancel-login.
const loginInProgressTTL = 5 * time.Minute

// stateEntry holds the current state and associated metadata for one cache key.
type stateEntry struct {
	state        AuthState
	loginStarted time.Time // set when transitioning to LOGIN_IN_PROGRESS
}

// StateManager tracks per-cacheKey authentication state.
// Thread-safe for concurrent access from multiple connection handlers.
type StateManager struct {
	mu      sync.RWMutex
	entries map[string]*stateEntry
}

// NewStateManager creates a new StateManager.
func NewStateManager() *StateManager {
	return &StateManager{
		entries: make(map[string]*stateEntry),
	}
}

// GetState returns the current state for a cache key.
// If LOGIN_IN_PROGRESS has exceeded TTL, auto-transitions to NEEDS_LOGIN.
// Returns NEEDS_LOGIN if no state has been set.
func (sm *StateManager) GetState(cacheKey string) (AuthState, time.Time) {
	sm.mu.RLock()
	entry, ok := sm.entries[cacheKey]
	if !ok {
		sm.mu.RUnlock()
		return StateNeedsLogin, time.Time{}
	}
	state := entry.state
	loginStarted := entry.loginStarted
	sm.mu.RUnlock()

	// Lazy TTL check: if LOGIN_IN_PROGRESS has expired, transition back
	if state == StateLoginInProgress && !loginStarted.IsZero() && time.Since(loginStarted) > loginInProgressTTL {
		sm.mu.Lock()
		// Re-check under write lock (another goroutine may have changed it)
		entry, ok = sm.entries[cacheKey]
		if ok && entry.state == StateLoginInProgress && !entry.loginStarted.IsZero() && time.Since(entry.loginStarted) > loginInProgressTTL {
			entry.state = StateNeedsLogin
			entry.loginStarted = time.Time{}
		}
		if ok {
			state = entry.state
			loginStarted = entry.loginStarted
		}
		sm.mu.Unlock()
	}

	return state, loginStarted
}

// SetState sets the state for a cache key.
func (sm *StateManager) SetState(cacheKey string, state AuthState) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entry, ok := sm.entries[cacheKey]
	if !ok {
		entry = &stateEntry{}
		sm.entries[cacheKey] = entry
	}
	entry.state = state
	if state == StateLoginInProgress {
		entry.loginStarted = time.Now()
	} else {
		entry.loginStarted = time.Time{}
	}
}

// BeginLogin transitions to LOGIN_IN_PROGRESS if not already in that state.
// Returns true if the transition was made, false if already LOGIN_IN_PROGRESS
// (along with when it started, so the caller can report elapsed time).
func (sm *StateManager) BeginLogin(cacheKey string) (ok bool, loginStarted time.Time) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entry, exists := sm.entries[cacheKey]
	if !exists {
		entry = &stateEntry{}
		sm.entries[cacheKey] = entry
	}

	// Check TTL expiry inline
	if entry.state == StateLoginInProgress && !entry.loginStarted.IsZero() && time.Since(entry.loginStarted) > loginInProgressTTL {
		entry.state = StateNeedsLogin
		entry.loginStarted = time.Time{}
	}

	if entry.state == StateLoginInProgress {
		return false, entry.loginStarted
	}

	entry.state = StateLoginInProgress
	entry.loginStarted = time.Now()
	return true, entry.loginStarted
}

// CancelLogin transitions from LOGIN_IN_PROGRESS back to NEEDS_LOGIN.
// No-op if not in LOGIN_IN_PROGRESS.
func (sm *StateManager) CancelLogin(cacheKey string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entry, ok := sm.entries[cacheKey]
	if !ok {
		return
	}
	if entry.state == StateLoginInProgress {
		entry.state = StateNeedsLogin
		entry.loginStarted = time.Time{}
	}
}

// DeleteEntry removes a state entry entirely (used during manager eviction).
func (sm *StateManager) DeleteEntry(cacheKey string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.entries, cacheKey)
}

// CompleteLogin transitions from LOGIN_IN_PROGRESS to VALID.
// No-op if not in LOGIN_IN_PROGRESS.
func (sm *StateManager) CompleteLogin(cacheKey string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	entry, ok := sm.entries[cacheKey]
	if !ok {
		entry = &stateEntry{}
		sm.entries[cacheKey] = entry
	}
	entry.state = StateValid
	entry.loginStarted = time.Time{}
}

// maxStateEntries is the upper bound on tracked cache keys.
// In practice a machine has ~1-5 OIDC providers; this prevents abuse.
const maxStateEntries = 1024

// EvictStale removes stale entries when the map exceeds maxStateEntries.
// First pass: remove NEEDS_LOGIN entries (truly idle).
// Second pass: remove expired LOGIN_IN_PROGRESS entries (TTL exceeded).
// Third pass: if still over limit, remove VALID and REFRESHING entries.
// Called periodically (e.g. from idle watcher) to bound memory growth.
func (sm *StateManager) EvictStale() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.entries) <= maxStateEntries {
		return
	}
	// First pass: evict NEEDS_LOGIN (cheapest to regenerate)
	for key, entry := range sm.entries {
		if entry.state == StateNeedsLogin {
			delete(sm.entries, key)
		}
	}
	if len(sm.entries) <= maxStateEntries {
		return
	}
	// Second pass: evict expired LOGIN_IN_PROGRESS (TTL exceeded, safe to remove)
	now := time.Now()
	for key, entry := range sm.entries {
		if entry.state == StateLoginInProgress && !entry.loginStarted.IsZero() && now.Sub(entry.loginStarted) > loginInProgressTTL {
			delete(sm.entries, key)
		}
	}
	if len(sm.entries) <= maxStateEntries {
		return
	}
	// Third pass: evict VALID and REFRESHING (they'll be re-derived on next access)
	for key, entry := range sm.entries {
		if entry.state == StateValid || entry.state == StateRefreshing {
			delete(sm.entries, key)
			if len(sm.entries) <= maxStateEntries {
				return
			}
		}
	}
}
