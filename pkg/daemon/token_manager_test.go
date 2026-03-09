package daemon

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockRefresher is a test Refresher that counts calls and returns configurable results.
type mockRefresher struct {
	mu         sync.Mutex
	callCount  int
	idToken    string
	refreshTok string
	expiry     time.Time
	err        error
	delay      time.Duration // simulate slow refresh
}

func (m *mockRefresher) Refresh(ctx context.Context, refreshToken string) (string, string, time.Time, error) {
	m.mu.Lock()
	m.callCount++
	delay := m.delay
	idToken := m.idToken
	refreshTok := m.refreshTok
	expiry := m.expiry
	err := m.err
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", "", time.Time{}, ctx.Err()
		}
	}
	return idToken, refreshTok, expiry, err
}

func (m *mockRefresher) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func newTestLogger(t *testing.T) *Logger {
	t.Helper()
	dir := t.TempDir()
	l, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestGetToken_LockFree(t *testing.T) {
	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  &mockRefresher{},
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	// No token set — should return empty
	_, _, ok := tm.GetToken()
	if ok {
		t.Error("GetToken should return false when no token is set")
	}

	// Set a token
	expiry := time.Now().Add(1 * time.Hour)
	tm.SetInitialToken("test-id-token", "test-refresh-token", expiry)

	// GetToken should return it immediately
	idToken, gotExpiry, ok := tm.GetToken()
	if !ok {
		t.Fatal("GetToken should return true after SetInitialToken")
	}
	if idToken != "test-id-token" {
		t.Errorf("want test-id-token, got %q", idToken)
	}
	if !gotExpiry.Equal(expiry) {
		t.Errorf("want %v, got %v", expiry, gotExpiry)
	}
}

func TestRefresh_SingleflightCoalesces(t *testing.T) {
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
		delay:      50 * time.Millisecond, // slow enough for concurrent calls to coalesce
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00bb11",
		Logger:     logger,
	})
	defer tm.Stop()

	// Set initial token
	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	// Launch 20 concurrent refreshes
	const n = 20
	var wg sync.WaitGroup
	var errCount atomic.Int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _, err := tm.Refresh(ctx)
			if err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if errCount.Load() > 0 {
		t.Errorf("%d/%d refreshes failed", errCount.Load(), n)
	}

	// singleflight should have coalesced all calls into exactly 1
	callCount := refresher.getCallCount()
	if callCount != 1 {
		t.Errorf("want exactly 1 refresh call (singleflight), got %d", callCount)
	}

	// Token should be updated
	idToken, _, ok := tm.GetToken()
	if !ok {
		t.Fatal("GetToken should return true after refresh")
	}
	if idToken != "new-id" {
		t.Errorf("want new-id, got %q", idToken)
	}
}

func TestRefresh_FailureKeepsOldToken(t *testing.T) {
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

	// Set initial token
	expiry := time.Now().Add(1 * time.Hour)
	tm.SetInitialToken("old-id", "old-rt", expiry)

	// Attempt refresh — should fail
	ctx := context.Background()
	_, _, err := tm.Refresh(ctx)
	if err == nil {
		t.Fatal("expected refresh to fail")
	}

	// Old token should still be available
	idToken, gotExpiry, ok := tm.GetToken()
	if !ok {
		t.Fatal("old token should still be available after failed refresh")
	}
	if idToken != "old-id" {
		t.Errorf("want old-id, got %q", idToken)
	}
	if !gotExpiry.Equal(expiry) {
		t.Error("expiry should be unchanged after failed refresh")
	}
}

func TestRefresh_PersistsAfterSuccess(t *testing.T) {
	dir := t.TempDir()
	refresher := &mockRefresher{
		idToken:    "persisted-id",
		refreshTok: "persisted-rt",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: dir,
		CacheKey:   "bb11cc22",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	ctx := context.Background()
	_, _, err := tm.Refresh(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Verify token was persisted
	gotID, gotRT, err := LoadPersistedToken(dir, "bb11cc22")
	if err != nil {
		t.Fatalf("load persisted: %v", err)
	}
	if gotID != "persisted-id" {
		t.Errorf("persisted id: want persisted-id, got %q", gotID)
	}
	if gotRT != "persisted-rt" {
		t.Errorf("persisted rt: want persisted-rt, got %q", gotRT)
	}
}

func TestRefresh_PersistFails(t *testing.T) {
	// Use an unwritable directory so PersistToken fails,
	// but refresh itself should still succeed and update the in-memory token.
	refresher := &mockRefresher{
		idToken:    "new-id",
		refreshTok: "new-rt",
		expiry:     time.Now().Add(1 * time.Hour),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: "/nonexistent-dir-that-does-not-exist",
		CacheKey:   "cc22dd33",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	ctx := context.Background()
	idToken, _, err := tm.Refresh(ctx)
	if err != nil {
		t.Fatalf("refresh should succeed even if persist fails: %v", err)
	}
	if idToken != "new-id" {
		t.Errorf("want new-id, got %q", idToken)
	}

	// Verify in-memory token was updated despite persist failure
	gotID, _, ok := tm.GetToken()
	if !ok {
		t.Fatal("GetToken should return true after refresh")
	}
	if gotID != "new-id" {
		t.Errorf("in-memory token not updated: want new-id, got %q", gotID)
	}
}

func TestConcurrentGetToken_NoRace(t *testing.T) {
	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  &mockRefresher{},
		PersistDir: t.TempDir(),
		CacheKey:   "dd33ee44",
		Logger:     logger,
	})
	defer tm.Stop()

	expiry := time.Now().Add(1 * time.Hour)
	tm.SetInitialToken("id", "rt", expiry)

	// 100 concurrent reads — should never race
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			token, _, ok := tm.GetToken()
			if !ok {
				t.Error("GetToken returned false")
			}
			if token != "id" {
				t.Errorf("want id, got %q", token)
			}
		}()
	}
	wg.Wait()
}

// TestPersistWatchdog_EmptyTokenGuard tests Bug 1.2: the persist watchdog
// must NOT write empty tokens to disk. After corrupt_token_files + kill_daemon,
// a new daemon starts with empty tokens; the watchdog must not overwrite the
// "no file" state with an empty-token file.
func TestPersistWatchdog_EmptyTokenGuard(t *testing.T) {
	persistDir := t.TempDir()
	logger := newTestLogger(t)

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:       &mockRefresher{},
		PersistDir:      persistDir,
		CacheKey:        "aa00cc11",
		Logger:          logger,
		PersistInterval: 50 * time.Millisecond, // short interval so watchdog fires quickly
	})

	// Set empty tokens (simulates daemon loading corrupt/empty state).
	tm.SetInitialToken("", "", time.Now().Add(1*time.Hour))

	// Wait for the watchdog to fire (at least 2 intervals).
	time.Sleep(150 * time.Millisecond)

	tm.Stop()

	// Verify no persist file was written.
	idToken, refreshToken, err := LoadPersistedToken(persistDir, "aa00cc11")
	if err != nil {
		t.Fatalf("LoadPersistedToken error: %v", err)
	}
	if idToken != "" || refreshToken != "" {
		t.Errorf("persist watchdog should NOT write empty tokens to disk, got id=%q rt=%q", idToken, refreshToken)
	}
}

// TestPersistWatchdog_WritesNonEmptyTokens verifies the watchdog DOES write
// non-empty tokens to disk (positive test for the guard).
func TestPersistWatchdog_WritesNonEmptyTokens(t *testing.T) {
	persistDir := t.TempDir()
	logger := newTestLogger(t)

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:       &mockRefresher{},
		PersistDir:      persistDir,
		CacheKey:        "aa00cc22",
		Logger:          logger,
		PersistInterval: 50 * time.Millisecond,
	})

	tm.SetInitialToken("some-id-token", "some-refresh-token", time.Now().Add(1*time.Hour))

	// Wait for the watchdog to fire.
	time.Sleep(150 * time.Millisecond)

	tm.Stop()

	// Verify the persist file was written.
	idToken, refreshToken, err := LoadPersistedToken(persistDir, "aa00cc22")
	if err != nil {
		t.Fatalf("LoadPersistedToken: %v", err)
	}
	if idToken != "some-id-token" {
		t.Errorf("want some-id-token, got %q", idToken)
	}
	if refreshToken != "some-refresh-token" {
		t.Errorf("want some-refresh-token, got %q", refreshToken)
	}
}

// TestRefresh_InvalidGrantIsPermanent tests that OIDC "invalid_grant" errors
// are classified as permanent (non-retryable) refresh failures.
func TestRefresh_InvalidGrantIsPermanent(t *testing.T) {
	refresher := &mockRefresher{
		err: fmt.Errorf("refresh token exchange: oauth2: %q: invalid_grant", "token revoked"),
	}

	logger := newTestLogger(t)
	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: t.TempDir(),
		CacheKey:   "aa00dd11",
		Logger:     logger,
	})
	defer tm.Stop()

	tm.SetInitialToken("old-id", "old-rt", time.Now().Add(1*time.Hour))

	_, _, err := tm.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh should return error for invalid_grant")
	}
	if !IsPermanentRefreshError(err) {
		t.Errorf("invalid_grant should be a permanent refresh error, got: %v", err)
	}
}
