package daemon

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Attack vector: Concurrent BeginLogin/CancelLogin/CompleteLogin from many goroutines
// trying to corrupt state or cause panics.
func TestAdversarial_StateMachine_RaceTornado(t *testing.T) {
	sm := NewStateManager()
	const goroutines = 200
	const opsPerGoroutine = 500
	var wg sync.WaitGroup

	keys := []string{"key1", "key2", "key3"}

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(id)))
			for i := 0; i < opsPerGoroutine; i++ {
				key := keys[rng.Intn(len(keys))]
				op := rng.Intn(7)
				switch op {
				case 0:
					sm.BeginLogin(key)
				case 1:
					sm.CancelLogin(key)
				case 2:
					sm.CompleteLogin(key)
				case 3:
					sm.SetState(key, StateValid)
				case 4:
					sm.SetState(key, StateNeedsLogin)
				case 5:
					sm.GetState(key)
				case 6:
					sm.EvictStale()
				}
			}
		}(g)
	}
	wg.Wait()
	// If we survive without panic/deadlock, pass
}

// Attack vector: CompleteLogin on a key that was never started — transitions
// to VALID unconditionally. Is this correct?
func TestAdversarial_CompleteLogin_WithoutBegin(t *testing.T) {
	sm := NewStateManager()

	// CompleteLogin without prior BeginLogin
	sm.CompleteLogin("never-started")

	state, _ := sm.GetState("never-started")
	// Bug: CompleteLogin creates a new entry and sets it to VALID
	// even without LOGIN_IN_PROGRESS. This means any caller can force
	// state to VALID for any key without going through the login flow.
	if state != StateValid {
		t.Errorf("CompleteLogin on unknown key: got %s (behavior may be intentional, but is it safe?)", state)
	}

	// More dangerous: CompleteLogin on a NEEDS_LOGIN key
	sm.SetState("needs-login-key", StateNeedsLogin)
	sm.CompleteLogin("needs-login-key")
	state, _ = sm.GetState("needs-login-key")
	if state != StateValid {
		t.Errorf("CompleteLogin on NEEDS_LOGIN key: got %s", state)
	}

	// CompleteLogin on a REFRESHING key — skips proper refresh flow
	sm.SetState("refreshing-key", StateRefreshing)
	sm.CompleteLogin("refreshing-key")
	state, _ = sm.GetState("refreshing-key")
	if state != StateValid {
		t.Errorf("CompleteLogin on REFRESHING key: got %s", state)
	}
}

// Attack vector: SetState to LOGIN_IN_PROGRESS bypasses BeginLogin's
// duplicate detection.
func TestAdversarial_SetState_BypassesBeginLoginGuard(t *testing.T) {
	sm := NewStateManager()

	// Normal flow: BeginLogin detects duplicate
	ok1, _ := sm.BeginLogin("key1")
	if !ok1 {
		t.Fatal("first BeginLogin should succeed")
	}
	ok2, _ := sm.BeginLogin("key1")
	if ok2 {
		t.Fatal("second BeginLogin should fail (duplicate detection)")
	}

	// Attack: SetState bypasses duplicate detection
	sm.SetState("key2", StateLoginInProgress)
	// Now BeginLogin returns false, but the loginStarted time was set by SetState
	ok3, started := sm.BeginLogin("key2")
	if ok3 {
		t.Error("BeginLogin after SetState(LOGIN_IN_PROGRESS) should return false")
	}
	// But the loginStarted time from SetState might differ from what BeginLogin would set
	if started.IsZero() {
		t.Error("loginStarted should not be zero after SetState(LOGIN_IN_PROGRESS)")
	}
}

// Attack vector: Race between GetState's TTL check and BeginLogin.
// GetState reads under RLock, sees expired LOGIN_IN_PROGRESS, acquires
// write lock to fix it. Meanwhile BeginLogin acquires write lock first.
func TestAdversarial_GetState_TTL_RaceWithBeginLogin(t *testing.T) {
	sm := NewStateManager()
	const iterations = 1000

	for iter := 0; iter < iterations; iter++ {
		key := fmt.Sprintf("race-key-%d", iter)

		// Set an expired LOGIN_IN_PROGRESS
		sm.mu.Lock()
		sm.entries[key] = &stateEntry{
			state:        StateLoginInProgress,
			loginStarted: time.Now().Add(-6 * time.Minute),
		}
		sm.mu.Unlock()

		// Race: GetState TTL expiry vs BeginLogin
		var wg sync.WaitGroup
		var getResult AuthState
		var beginOk bool

		wg.Add(2)
		go func() {
			defer wg.Done()
			getResult, _ = sm.GetState(key)
		}()
		go func() {
			defer wg.Done()
			beginOk, _ = sm.BeginLogin(key)
		}()
		wg.Wait()

		// Both should see the TTL expiry, but the final state should be
		// consistent: either NEEDS_LOGIN (TTL expired, no new login) or
		// LOGIN_IN_PROGRESS (new login started)
		finalState, _ := sm.GetState(key)
		if finalState != StateNeedsLogin && finalState != StateLoginInProgress {
			t.Errorf("iter %d: unexpected final state %s", iter, finalState)
		}
		// Suppress unused warnings
		_ = getResult
		_ = beginOk
	}
}

// Attack vector: Overflow maxStateEntries, then verify EvictStale behavior.
// Specifically: if all entries are LOGIN_IN_PROGRESS, EvictStale cannot
// reduce below maxStateEntries. Memory grows unbounded.
func TestAdversarial_EvictStale_AllLoginInProgress(t *testing.T) {
	sm := NewStateManager()

	// Fill with LOGIN_IN_PROGRESS entries (cannot be evicted)
	for i := 0; i < maxStateEntries+500; i++ {
		sm.BeginLogin(fmt.Sprintf("login-%d", i))
	}

	sm.EvictStale()

	sm.mu.RLock()
	count := len(sm.entries)
	sm.mu.RUnlock()

	// All entries are LOGIN_IN_PROGRESS, so EvictStale cannot remove any.
	// This is a potential memory exhaustion attack vector.
	if count <= maxStateEntries {
		t.Errorf("expected > %d entries (all LOGIN_IN_PROGRESS cannot be evicted), got %d", maxStateEntries, count)
	} else {
		t.Logf("FINDING: EvictStale cannot bound memory when all %d entries are LOGIN_IN_PROGRESS (denial-of-service vector)", count)
	}
}

// Attack vector: EvictStale while concurrent reads/writes are happening.
func TestAdversarial_EvictStale_ConcurrentWithReadWrite(t *testing.T) {
	sm := NewStateManager()
	const goroutines = 50
	var wg sync.WaitGroup

	// Fill past maxStateEntries
	for i := 0; i < maxStateEntries+100; i++ {
		sm.SetState(fmt.Sprintf("stale-%d", i), StateNeedsLogin)
	}

	// Concurrent eviction, reads, and writes
	wg.Add(goroutines * 3)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			sm.EvictStale()
		}()
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				sm.GetState(fmt.Sprintf("stale-%d", id*100+i))
			}
		}(g)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				sm.SetState(fmt.Sprintf("new-%d-%d", id, i), StateValid)
			}
		}(g)
	}
	wg.Wait()
}

// Attack vector: Rapid state transitions on the same key.
// BeginLogin -> CompleteLogin -> BeginLogin -> CancelLogin in tight loop.
func TestAdversarial_RapidStateTransitions(t *testing.T) {
	sm := NewStateManager()
	const iterations = 10000

	for i := 0; i < iterations; i++ {
		ok, _ := sm.BeginLogin("rapid-key")
		if !ok {
			// If BeginLogin fails, someone else got there first — cancel and retry
			sm.CancelLogin("rapid-key")
			continue
		}
		sm.CompleteLogin("rapid-key")
	}

	// Final state should be VALID (last CompleteLogin wins)
	state, _ := sm.GetState("rapid-key")
	if state != StateValid && state != StateNeedsLogin {
		t.Errorf("unexpected final state after rapid transitions: %s", state)
	}
}

// Attack vector: Empty string cache key. This is allowed by StateManager
// but might cause issues elsewhere.
func TestAdversarial_EmptyStringCacheKey(t *testing.T) {
	sm := NewStateManager()

	// Empty string key
	sm.SetState("", StateValid)
	state, _ := sm.GetState("")
	if state != StateValid {
		t.Errorf("empty key: want VALID, got %s", state)
	}

	ok, _ := sm.BeginLogin("")
	if ok {
		t.Log("BeginLogin succeeded on empty key — transitions from VALID to LOGIN_IN_PROGRESS")
	}
}

// Attack vector: Very long cache keys (potential memory issue).
func TestAdversarial_VeryLongCacheKey(t *testing.T) {
	sm := NewStateManager()

	// 1MB cache key
	longKey := make([]byte, 1<<20)
	for i := range longKey {
		longKey[i] = 'a'
	}

	sm.SetState(string(longKey), StateValid)
	state, _ := sm.GetState(string(longKey))
	if state != StateValid {
		t.Errorf("long key: want VALID, got %s", state)
	}
}

// Attack vector: Verify that GetState's lazy TTL check doesn't lose
// state updates. Scenario: GetState sees expired LIP, takes write lock,
// but by then CompleteLogin already set it to VALID.
func TestAdversarial_GetState_TTL_CompetesWithCompleteLogin(t *testing.T) {
	sm := NewStateManager()
	const iterations = 5000

	var validCount, needsLoginCount atomic.Int32

	for iter := 0; iter < iterations; iter++ {
		key := fmt.Sprintf("ttl-race-%d", iter)

		// Set expired LOGIN_IN_PROGRESS
		sm.mu.Lock()
		sm.entries[key] = &stateEntry{
			state:        StateLoginInProgress,
			loginStarted: time.Now().Add(-6 * time.Minute),
		}
		sm.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		// GetState will try to transition LIP -> NEEDS_LOGIN (TTL)
		go func() {
			defer wg.Done()
			sm.GetState(key)
		}()
		// CompleteLogin will try to transition -> VALID
		go func() {
			defer wg.Done()
			sm.CompleteLogin(key)
		}()
		wg.Wait()

		state, _ := sm.GetState(key)
		switch state {
		case StateValid:
			validCount.Add(1)
		case StateNeedsLogin:
			needsLoginCount.Add(1)
		default:
			t.Errorf("iter %d: unexpected state %s after GetState+CompleteLogin race", iter, state)
		}
	}

	t.Logf("Results: VALID=%d, NEEDS_LOGIN=%d (both are valid outcomes depending on ordering)",
		validCount.Load(), needsLoginCount.Load())
}

// Attack vector: CancelLogin on a key that doesn't exist.
func TestAdversarial_CancelLogin_NonexistentKey(t *testing.T) {
	sm := NewStateManager()
	// Should not panic
	sm.CancelLogin("does-not-exist")
	state, _ := sm.GetState("does-not-exist")
	if state != StateNeedsLogin {
		t.Errorf("cancel on nonexistent: want NEEDS_LOGIN, got %s", state)
	}
}

// Attack vector: SetState with invalid AuthState value.
func TestAdversarial_SetState_InvalidAuthState(t *testing.T) {
	sm := NewStateManager()
	// AuthState is just a string type — no validation
	sm.SetState("bad-state-key", AuthState("COMPLETELY_INVALID_STATE"))
	state, _ := sm.GetState("bad-state-key")
	if state != AuthState("COMPLETELY_INVALID_STATE") {
		t.Errorf("expected invalid state to be stored as-is, got %s", state)
	}
	// This is a design issue: no validation on state transitions
	t.Log("FINDING: SetState accepts arbitrary AuthState values with no validation")
}

// Attack vector: Concurrent BeginLogin on the same key — only one should win.
func TestAdversarial_ConcurrentBeginLogin_OnlyOneWins(t *testing.T) {
	sm := NewStateManager()
	const goroutines = 100
	var wg sync.WaitGroup
	var successCount atomic.Int32

	wg.Add(goroutines)
	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			<-start
			ok, _ := sm.BeginLogin("contest-key")
			if ok {
				successCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successCount.Load() != 1 {
		t.Errorf("expected exactly 1 BeginLogin success, got %d", successCount.Load())
	}
}

// Attack vector: GetState returns stale data from RLock read when
// state is being modified concurrently.
func TestAdversarial_GetState_Staleness(t *testing.T) {
	sm := NewStateManager()
	sm.SetState("stale-key", StateValid)

	const goroutines = 100
	var wg sync.WaitGroup
	var invalidStates atomic.Int32

	wg.Add(goroutines * 2)
	for g := 0; g < goroutines; g++ {
		// Writers: toggle between VALID and NEEDS_LOGIN
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if i%2 == 0 {
					sm.SetState("stale-key", StateValid)
				} else {
					sm.SetState("stale-key", StateNeedsLogin)
				}
			}
		}()
		// Readers: check that we only see valid AuthState values
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				state, _ := sm.GetState("stale-key")
				switch state {
				case StateValid, StateNeedsLogin, StateRefreshing, StateLoginInProgress:
					// ok
				default:
					invalidStates.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if invalidStates.Load() > 0 {
		t.Errorf("observed %d invalid states during concurrent access", invalidStates.Load())
	}
}
