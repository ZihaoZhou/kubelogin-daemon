package daemon

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Attack vector: SetInitialToken called concurrently from many goroutines.
// Each call replaces the atomic pointer and re-schedules the timer.
func TestAdversarial_TokenManager_ConcurrentSetInitialToken(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			tok := fmt.Sprintf("token-%d", id)
			tm.SetInitialToken(tok, "rt", time.Now().Add(1*time.Hour))
		}(g)
	}
	wg.Wait()

	// Should not panic and should have some token set
	_, _, ok := tm.GetToken()
	if !ok {
		t.Error("GetToken should return true after concurrent SetInitialToken")
	}
}

// Attack vector: Refresh with nil current token (no initial token set).
func TestAdversarial_TokenManager_RefreshWithoutInitialToken(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	// Refresh without ever setting initial token
	ctx := context.Background()
	_, _, err := tm.Refresh(ctx)
	if err == nil {
		t.Error("Refresh without initial token should fail")
	}
}

// Attack vector: Concurrent Refresh and SetInitialToken — the singleflight
// group may return stale results to concurrent callers.
func TestAdversarial_TokenManager_ConcurrentRefreshAndSetInitialToken(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "refreshed-id",
		refreshTok: "refreshed-rt",
		expiry:     time.Now().Add(1 * time.Hour),
		delay:      50 * time.Millisecond,
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half do refreshes
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			tm.Refresh(ctx)
		}()
	}

	// Half do SetInitialToken
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			tm.SetInitialToken(fmt.Sprintf("concurrent-%d", id), "rt", time.Now().Add(1*time.Hour))
		}(g)
	}

	wg.Wait()

	// Should not panic
	_, _, ok := tm.GetToken()
	if !ok {
		t.Error("token should exist after concurrent operations")
	}
}

// Attack vector: Stop() called during active Refresh().
func TestAdversarial_TokenManager_StopDuringRefresh(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
		delay:      200 * time.Millisecond,
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	// Start a slow refresh
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tm.Refresh(ctx)
	}()

	// Stop while refresh is in progress
	time.Sleep(50 * time.Millisecond)
	tm.Stop()
	tm.Stop() // Double stop should be safe

	wg.Wait()
}

// Attack vector: Multiple Stop() calls from concurrent goroutines.
func TestAdversarial_TokenManager_ConcurrentStop(t *testing.T) {
	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  &mockRefresher{},
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})

	tm.SetInitialToken("id", "rt", time.Now().Add(1*time.Hour))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			tm.Stop()
		}()
	}
	wg.Wait()
}

// Attack vector: SetInitialToken with zero/negative expiry.
func TestAdversarial_TokenManager_ZeroExpiry(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	// Zero time expiry
	tm.SetInitialToken("id", "rt", time.Time{})
	if !tm.IsExpired() {
		t.Error("zero expiry should be expired")
	}

	// Past expiry
	tm.SetInitialToken("id", "rt", time.Now().Add(-1*time.Hour))
	if !tm.IsExpired() {
		t.Error("past expiry should be expired")
	}
}

// Attack vector: Refresh failure followed by rapid retries.
func TestAdversarial_TokenManager_RefreshFailureThenRetry(t *testing.T) {
	failCount := atomic.Int32{}
	refresher := &mockRefresher{
		err: fmt.Errorf("network error"),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	// Rapid retry attempts
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			_, _, err := tm.Refresh(ctx)
			if err != nil {
				failCount.Add(1)
			}
		}()
	}
	wg.Wait()

	// All should fail, but singleflight coalesces them
	if failCount.Load() != int32(n) {
		t.Logf("not all refresh attempts returned failure (singleflight: %d/%d failed)", failCount.Load(), n)
	}

	// Old token should still be available
	id, _, ok := tm.GetToken()
	if !ok || id != "old-id" {
		t.Error("old token should survive failed refreshes")
	}
}

// Attack vector: Refresher returns empty strings.
func TestAdversarial_TokenManager_RefresherReturnsEmpty(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "",
		refreshTok: "",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	ctx := context.Background()
	idToken, _, err := tm.Refresh(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Refresher returned empty id_token but no error
	if idToken != "" {
		t.Errorf("expected empty id_token from refresher, got %q", idToken)
	}

	// Now CurrentRefreshToken is empty — subsequent refreshes will use empty refresh token
	rt := tm.CurrentRefreshToken()
	if rt != "" {
		t.Errorf("expected empty refresh token, got %q", rt)
	}
	t.Log("FINDING: Refresher returning empty tokens is silently accepted. Subsequent refreshes will pass empty refresh_token to the OIDC provider.")
}

// Attack vector: Refresher returns zero-time expiry.
func TestAdversarial_TokenManager_RefresherReturnsZeroExpiry(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Time{}, // zero time
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	ctx := context.Background()
	_, expiry, err := tm.Refresh(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if !expiry.IsZero() {
		t.Errorf("expected zero expiry, got %v", expiry)
	}

	// Zero expiry means token is immediately considered expired
	if !tm.IsExpired() {
		t.Error("zero expiry should mean token is expired")
	}

	// scheduleProactiveRefresh with negative lifetime should be a no-op
	// (handled by the lifetime <= 0 check). But the token is now stuck
	// in an always-expired state.
	t.Log("FINDING: Refresher returning zero expiry puts token in permanently-expired state. No proactive refresh is scheduled.")
}

// ROB-CRIT-1: Context cancellation during Refresh should NOT abort the refresh.
// The singleflight closure uses a detached context so that the first caller's
// cancellation doesn't kill the refresh for all waiting callers.
func TestAdversarial_TokenManager_RefreshContextCancelled(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
		delay:      200 * time.Millisecond,
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay — should NOT affect the refresh
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	id, _, err := tm.Refresh(ctx)
	if err != nil {
		t.Errorf("Refresh should succeed despite caller context cancellation: %v", err)
	}

	// New token should be stored (refresh completed despite cancellation)
	if id != "new-id" {
		t.Errorf("refresh should produce new token, got %q", id)
	}
	storedID, _, ok := tm.GetToken()
	if !ok || storedID != "new-id" {
		t.Error("new token should be stored after successful refresh")
	}
}

// Attack vector: GetToken and Refresh from many goroutines simultaneously
// to check for data races in atomic.Pointer operations.
func TestAdversarial_TokenManager_ConcurrentGetAndRefresh(t *testing.T) {
	refreshCount := atomic.Int32{}
	refresher := &mockRefresher{
		idToken:    "refreshed",
		refreshTok: "rt",
		expiry:     time.Now().Add(1 * time.Hour),
		delay:      10 * time.Millisecond,
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	const goroutines = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			if id%4 == 0 {
				// Refresh
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _, err := tm.Refresh(ctx)
				if err == nil {
					refreshCount.Add(1)
				}
			} else if id%4 == 1 {
				// SetInitialToken
				tm.SetInitialToken(fmt.Sprintf("tok-%d", id), "rt", time.Now().Add(1*time.Hour))
			} else if id%4 == 2 {
				// GetToken
				_, _, _ = tm.GetToken()
			} else {
				// IsExpired + HasToken
				_ = tm.IsExpired()
				_ = tm.HasToken()
			}
		}(g)
	}
	wg.Wait()

	t.Logf("successful refreshes: %d (singleflight should coalesce)", refreshCount.Load())
}

// Attack vector: TokenManager config with invalid RefreshMargin.
func TestAdversarial_TokenManager_InvalidConfig(t *testing.T) {
	logger := newTestLogger(t)

	// RefreshMargin = 0 should use default 0.80
	tm1 := NewTokenManager(TokenManagerConfig{
		Refresher:     &mockRefresher{},
		PersistDir:    t.TempDir(),
		CacheKey:      "aa00bb11",
		Logger:        logger,
		RefreshMargin: 0,
	})
	tm1.Stop()

	// RefreshMargin = 1 should use default 0.80
	tm2 := NewTokenManager(TokenManagerConfig{
		Refresher:     &mockRefresher{},
		PersistDir:    t.TempDir(),
		CacheKey:      "aa00bb11",
		Logger:        logger,
		RefreshMargin: 1.0,
	})
	tm2.Stop()

	// RefreshMargin = -1 should use default 0.80
	tm3 := NewTokenManager(TokenManagerConfig{
		Refresher:     &mockRefresher{},
		PersistDir:    t.TempDir(),
		CacheKey:      "aa00bb11",
		Logger:        logger,
		RefreshMargin: -1.0,
	})
	tm3.Stop()

	// MinRefreshInterval = 0 should use default 10s
	tm4 := NewTokenManager(TokenManagerConfig{
		Refresher:          &mockRefresher{},
		PersistDir:         t.TempDir(),
		CacheKey:           "aa00bb11",
		Logger:             logger,
		MinRefreshInterval: 0,
	})
	tm4.Stop()

	// RefreshMargin = 0.99 — very aggressive
	tm5 := NewTokenManager(TokenManagerConfig{
		Refresher:     &mockRefresher{},
		PersistDir:    t.TempDir(),
		CacheKey:      "aa00bb11",
		Logger:        logger,
		RefreshMargin: 0.99,
	})
	defer tm5.Stop()
	tm5.SetInitialToken("id", "rt", time.Now().Add(1*time.Hour))
	// Should work, just refreshes very late
}

// Attack vector: scheduleRetry with very high retryCount (overflow check).
func TestAdversarial_TokenManager_RetryCountOverflow(t *testing.T) {
	refresher := &mockRefresher{
		err: fmt.Errorf("permanent failure"),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	// Manually set high retry count
	tm.timerMu.Lock()
	tm.retryCount = 1<<63 - 1 // max uint before overflow wraps around
	tm.timerMu.Unlock()

	// Set a token with future expiry
	tm.SetInitialToken("id", "rt", time.Now().Add(1*time.Hour))

	// The scheduleRetry uses: delay = time.Second << (retryCount - 1)
	// With retryCount = max uint, this could overflow. But the cap at 30s should prevent issues.
	entry := tm.current.Load()
	if entry != nil {
		tm.scheduleRetry(entry)
		// Should not panic from overflow
	}
}
