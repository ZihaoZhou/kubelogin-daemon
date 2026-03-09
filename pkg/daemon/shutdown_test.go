package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// shutdownTestRefresher is a function-based Refresher for shutdown tests.
type shutdownTestRefresher struct {
	refreshFn func(ctx context.Context, refreshToken string) (string, string, time.Time, error)
}

func (m *shutdownTestRefresher) Refresh(ctx context.Context, refreshToken string) (string, string, time.Time, error) {
	return m.refreshFn(ctx, refreshToken)
}

// TestB4_ShutdownDuringRetry_ExitsPromptly verifies that when the daemon is
// in a retry loop and shutdown is requested, it exits within the deadline
// (5s + 1s margin = 6s), NOT after the retry backoff completes.
func TestB4_ShutdownDuringRetry_ExitsPromptly(t *testing.T) {
	dir := t.TempDir()
	rtDir := filepath.Join(dir, "rt")
	if err := os.Mkdir(rtDir, 0700); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(dir, "log")
	if err := os.Mkdir(logDir, 0700); err != nil {
		t.Fatal(err)
	}
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// Mock refresher that always fails (simulates provider outage)
	mock := &shutdownTestRefresher{
		refreshFn: func(ctx context.Context, rt string) (string, string, time.Time, error) {
			// Check for context cancellation
			select {
			case <-ctx.Done():
				return "", "", time.Time{}, ctx.Err()
			default:
			}
			return "", "", time.Time{}, fmt.Errorf("mock: provider unavailable")
		},
	}

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:          mock,
		PersistDir:         rtDir,
		CacheKey:           "test",
		Logger:             logger,
		MinRefreshInterval: 50 * time.Millisecond, // fast for testing
	})

	// Set a token that will expire soon to trigger proactive refresh.
	// With 500ms expiry and 80% margin, proactive refresh fires at 400ms.
	// MinRefreshInterval is 50ms, so it won't clamp.
	tm.SetInitialToken("test-token", "test-refresh",
		time.Now().Add(500*time.Millisecond))

	// Wait for the first refresh attempt to fail and enter retry loop.
	// The proactive refresh fires at ~400ms, fails immediately, then
	// schedules a retry with ~1s backoff. We wait long enough for
	// the first attempt to fire and fail.
	time.Sleep(800 * time.Millisecond)

	// Now stop — should complete within 6 seconds
	start := time.Now()
	done := make(chan struct{})
	go func() {
		tm.Stop()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed > 6*time.Second {
			t.Fatalf("Stop() took %s (want <6s)", elapsed)
		}
		t.Logf("Stop() completed in %s", elapsed.Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		t.Fatal("Stop() did not complete within 10s — shutdown deadline exceeded")
	}
}

// TestB4_ShutdownDuringProactiveRefresh verifies that a proactive refresh
// in progress is interrupted when Stop() is called.
func TestB4_ShutdownDuringProactiveRefresh(t *testing.T) {
	dir := t.TempDir()
	rtDir := filepath.Join(dir, "rt")
	if err := os.Mkdir(rtDir, 0700); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(dir, "log")
	if err := os.Mkdir(logDir, 0700); err != nil {
		t.Fatal(err)
	}
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	refreshStarted := make(chan struct{}, 1)
	// Mock refresher that blocks until context cancelled
	mock := &shutdownTestRefresher{
		refreshFn: func(ctx context.Context, rt string) (string, string, time.Time, error) {
			select {
			case refreshStarted <- struct{}{}:
			default:
			}
			<-ctx.Done()
			return "", "", time.Time{}, ctx.Err()
		},
	}

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:          mock,
		PersistDir:         rtDir,
		CacheKey:           "test",
		Logger:             logger,
		MinRefreshInterval: 50 * time.Millisecond, // fast for testing
	})

	// Set a token that expires very soon to trigger immediate proactive refresh.
	// With 200ms expiry and 80% margin, proactive refresh fires at 160ms.
	// MinRefreshInterval is 50ms, so it won't clamp the delay.
	tm.SetInitialToken("test-token", "test-refresh",
		time.Now().Add(200*time.Millisecond))

	// Wait for refresh to start
	select {
	case <-refreshStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start within 5s")
	}

	// Stop should interrupt the in-flight refresh
	start := time.Now()
	tm.Stop()
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("Stop() with in-flight refresh took %s (want <3s)", elapsed)
	}
	t.Logf("Stop() with in-flight refresh completed in %s", elapsed.Round(time.Millisecond))
}
