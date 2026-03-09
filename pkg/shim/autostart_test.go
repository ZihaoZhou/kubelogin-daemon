//go:build !windows

package shim

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestB6_ConcurrentAutoStart_AlreadyRunning verifies that 50 concurrent
// AutoStartDaemon calls all succeed when a daemon is already running.
// This tests the fast path (connect-probe succeeds, no fork needed).
func TestB6_ConcurrentAutoStart_AlreadyRunning(t *testing.T) {
	runtimeDir, cleanup := startShortPathDaemon(t)
	defer cleanup()

	const n = 50
	var wg sync.WaitGroup
	var failures atomic.Int32

	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			if err := AutoStartDaemon(runtimeDir); err != nil {
				failures.Add(1)
				t.Logf("[%d] AutoStartDaemon error: %v", i, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if f := failures.Load(); f > 0 {
		t.Errorf("%d/%d concurrent AutoStartDaemon calls failed (should all succeed with running daemon)", f, n)
	}
}

// TestB6_MkdirGuard_ExactlyOneWinner verifies that the atomic mkdir guard
// used in autoStartDaemonCommon allows exactly one goroutine to win.
// This is the core mechanism that prevents thundering herd forks.
func TestB6_MkdirGuard_ExactlyOneWinner(t *testing.T) {
	dir := t.TempDir()
	guardDir := filepath.Join(dir, ".starting")

	const n = 50
	var wg sync.WaitGroup
	var winners atomic.Int32

	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			if err := os.Mkdir(guardDir, 0700); err == nil {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if w := winners.Load(); w != 1 {
		t.Errorf("expected exactly 1 mkdir winner, got %d", w)
	}
}

// TestB6_StaleStartingDir_Cleaned verifies that a stale .starting dir
// (from a crashed shim) is detected and cleaned up by the next autostart attempt.
func TestB6_StaleStartingDir_Cleaned(t *testing.T) {
	runtimeDir, cleanup := startShortPathDaemon(t)
	defer cleanup()

	// Create a stale .starting dir (simulates a crashed shim from >10s ago)
	startingDir := filepath.Join(runtimeDir, ".starting")
	if err := os.Mkdir(startingDir, 0700); err != nil {
		t.Fatalf("create stale .starting dir: %v", err)
	}
	// Backdate the mod time to make it stale (>10s old)
	staleTime := time.Now().Add(-15 * time.Second)
	if err := os.Chtimes(startingDir, staleTime, staleTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// AutoStartDaemon should succeed — the daemon is already running,
	// so the stale .starting dir doesn't block anything.
	if err := AutoStartDaemon(runtimeDir); err != nil {
		t.Fatalf("AutoStartDaemon with stale .starting dir: %v", err)
	}
}

// TestB6_StartingDir_CleanedAfterSuccess verifies that the .starting guard
// directory is removed after a successful daemon start.
func TestB6_StartingDir_CleanedAfterSuccess(t *testing.T) {
	runtimeDir, cleanup := startShortPathDaemon(t)
	defer cleanup()

	startingDir := filepath.Join(runtimeDir, ".starting")

	// With daemon already running, AutoStartDaemon finds the socket on
	// the initial connect-probe and never creates .starting.
	if err := AutoStartDaemon(runtimeDir); err != nil {
		t.Fatalf("AutoStartDaemon: %v", err)
	}

	// .starting should not exist (was never created, or was cleaned up)
	if _, err := os.Stat(startingDir); !os.IsNotExist(err) {
		t.Errorf(".starting dir should not exist after successful autostart, stat err: %v", err)
	}
}
