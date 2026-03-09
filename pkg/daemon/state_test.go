package daemon

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestStateManager_DefaultState(t *testing.T) {
	sm := NewStateManager()
	state, loginStarted := sm.GetState("unknown-key")
	if state != StateNeedsLogin {
		t.Errorf("want NEEDS_LOGIN for unknown key, got %s", state)
	}
	if !loginStarted.IsZero() {
		t.Errorf("want zero loginStarted for unknown key, got %v", loginStarted)
	}
}

func TestStateManager_SetAndGetState(t *testing.T) {
	sm := NewStateManager()
	sm.SetState("key1", StateValid)
	state, _ := sm.GetState("key1")
	if state != StateValid {
		t.Errorf("want VALID, got %s", state)
	}

	sm.SetState("key1", StateRefreshing)
	state, _ = sm.GetState("key1")
	if state != StateRefreshing {
		t.Errorf("want REFRESHING, got %s", state)
	}
}

func TestStateManager_BeginLogin(t *testing.T) {
	sm := NewStateManager()

	// First login should succeed
	ok, started := sm.BeginLogin("key1")
	if !ok {
		t.Error("first BeginLogin should succeed")
	}
	if started.IsZero() {
		t.Error("loginStarted should be set")
	}

	// Second login should detect in-progress
	ok2, started2 := sm.BeginLogin("key1")
	if ok2 {
		t.Error("second BeginLogin should return false (already in progress)")
	}
	if started2.IsZero() {
		t.Error("should return original loginStarted time")
	}

	state, _ := sm.GetState("key1")
	if state != StateLoginInProgress {
		t.Errorf("want LOGIN_IN_PROGRESS, got %s", state)
	}
}

func TestStateManager_CancelLogin(t *testing.T) {
	sm := NewStateManager()
	sm.BeginLogin("key1")

	sm.CancelLogin("key1")
	state, _ := sm.GetState("key1")
	if state != StateNeedsLogin {
		t.Errorf("want NEEDS_LOGIN after cancel, got %s", state)
	}

	// Cancel on non-LOGIN_IN_PROGRESS is a no-op
	sm.SetState("key1", StateValid)
	sm.CancelLogin("key1")
	state, _ = sm.GetState("key1")
	if state != StateValid {
		t.Errorf("cancel should be no-op on VALID state, got %s", state)
	}
}

func TestStateManager_CompleteLogin(t *testing.T) {
	sm := NewStateManager()
	sm.BeginLogin("key1")

	sm.CompleteLogin("key1")
	state, _ := sm.GetState("key1")
	if state != StateValid {
		t.Errorf("want VALID after complete, got %s", state)
	}
}

func TestStateManager_LoginTTLExpiry(t *testing.T) {
	sm := NewStateManager()

	// Manually set LOGIN_IN_PROGRESS with an old timestamp
	sm.mu.Lock()
	sm.entries["key1"] = &stateEntry{
		state:        StateLoginInProgress,
		loginStarted: time.Now().Add(-6 * time.Minute), // > 5 min TTL
	}
	sm.mu.Unlock()

	// GetState should auto-transition to NEEDS_LOGIN
	state, _ := sm.GetState("key1")
	if state != StateNeedsLogin {
		t.Errorf("want NEEDS_LOGIN after TTL expiry, got %s", state)
	}
}

func TestStateManager_BeginLoginAfterTTLExpiry(t *testing.T) {
	sm := NewStateManager()

	// Set an expired LOGIN_IN_PROGRESS
	sm.mu.Lock()
	sm.entries["key1"] = &stateEntry{
		state:        StateLoginInProgress,
		loginStarted: time.Now().Add(-6 * time.Minute),
	}
	sm.mu.Unlock()

	// BeginLogin should succeed because the old one expired
	ok, _ := sm.BeginLogin("key1")
	if !ok {
		t.Error("BeginLogin should succeed after TTL expiry")
	}

	state, _ := sm.GetState("key1")
	if state != StateLoginInProgress {
		t.Errorf("want LOGIN_IN_PROGRESS, got %s", state)
	}
}

func TestStateManager_ConcurrentAccess(t *testing.T) {
	sm := NewStateManager()
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n * 3) // readers, writers, begin-logins

	// Concurrent readers
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			sm.GetState("concurrent-key")
		}()
	}

	// Concurrent writers
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				sm.SetState("concurrent-key", StateValid)
			} else {
				sm.SetState("concurrent-key", StateNeedsLogin)
			}
		}(i)
	}

	// Concurrent begin-logins
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			sm.BeginLogin("concurrent-key")
		}()
	}

	wg.Wait()
	// If we get here without panic/race, the test passes
}

func TestStateManager_IsolationBetweenKeys(t *testing.T) {
	sm := NewStateManager()
	sm.SetState("keyA", StateValid)
	sm.SetState("keyB", StateNeedsLogin)
	sm.BeginLogin("keyC")

	stateA, _ := sm.GetState("keyA")
	stateB, _ := sm.GetState("keyB")
	stateC, _ := sm.GetState("keyC")

	if stateA != StateValid {
		t.Errorf("keyA: want VALID, got %s", stateA)
	}
	if stateB != StateNeedsLogin {
		t.Errorf("keyB: want NEEDS_LOGIN, got %s", stateB)
	}
	if stateC != StateLoginInProgress {
		t.Errorf("keyC: want LOGIN_IN_PROGRESS, got %s", stateC)
	}
}

func TestStateManager_EvictStale(t *testing.T) {
	sm := NewStateManager()

	// Add entries of various states
	sm.SetState("valid1", StateValid)
	sm.SetState("needs1", StateNeedsLogin)
	sm.SetState("needs2", StateNeedsLogin)
	sm.BeginLogin("login1")

	// Below max threshold — eviction is a no-op
	sm.EvictStale()
	state, _ := sm.GetState("needs1")
	if state != StateNeedsLogin {
		t.Errorf("needs1 should still exist below threshold, got %s", state)
	}

	// Fill to over maxStateEntries
	for i := 0; i < maxStateEntries+10; i++ {
		sm.SetState(fmt.Sprintf("stale-%d", i), StateNeedsLogin)
	}
	sm.EvictStale()

	// VALID and LOGIN_IN_PROGRESS entries should survive
	stateV, _ := sm.GetState("valid1")
	if stateV != StateValid {
		t.Errorf("valid1 should survive eviction, got %s", stateV)
	}
	stateL, _ := sm.GetState("login1")
	if stateL != StateLoginInProgress {
		t.Errorf("login1 should survive eviction, got %s", stateL)
	}

	// NEEDS_LOGIN entries should be evicted
	sm.mu.RLock()
	count := len(sm.entries)
	sm.mu.RUnlock()
	if count > maxStateEntries {
		t.Errorf("after eviction, entries should be <= %d, got %d", maxStateEntries, count)
	}
}
