package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestB1_BindFailure_ExitsImmediately verifies that when a daemon is already
// listening, a second daemon attempting to start exits immediately rather than
// hanging. This is the root cause of orphan process accumulation (B1).
func TestB1_BindFailure_ExitsImmediately(t *testing.T) {
	srvA, dir := newTestServer(t, 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start daemon A
	errCh := make(chan error, 1)
	go func() { errCh <- srvA.ListenAndServe(ctx) }()
	waitForServerReady(t, srvA.SocketPath())

	// Start daemon B targeting the same socket — must exit within 3 seconds.
	srvB := NewServer(ServerConfig{
		RuntimeDir:    dir,
		Logger:        srvA.logger,
		IdleTimeout:   10 * time.Minute,
		IdleCheckTick: 1 * time.Second,
	})
	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()

	bErr := make(chan error, 1)
	start := time.Now()
	go func() { bErr <- srvB.ListenAndServe(bCtx) }()

	select {
	case err := <-bErr:
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Fatalf("daemon B took %s to exit (want <3s)", elapsed)
		}
		if err == nil {
			t.Fatal("daemon B should have returned an error, got nil")
		}
		t.Logf("daemon B exited in %s with: %v", elapsed.Round(time.Millisecond), err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon B did not exit within 5 seconds (orphan!)")
	}

	// Verify daemon A is still healthy
	conn, err := net.DialTimeout("unix", srvA.SocketPath(), 2*time.Second)
	if err != nil {
		t.Fatalf("daemon A not healthy after B's failed start: %v", err)
	}
	conn.Close()

	// Clean up
	cancel()
	srvA.Shutdown()
}

// TestB1_ConcurrentBindFailure_AllExit verifies that 20 concurrent daemons
// all exit promptly when racing against a running daemon.
func TestB1_ConcurrentBindFailure_AllExit(t *testing.T) {
	srvA, dir := newTestServer(t, 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srvA.ListenAndServe(ctx) }()
	waitForServerReady(t, srvA.SocketPath())

	const n = 20
	var wg sync.WaitGroup
	var exited atomic.Int32
	start := time.Now()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv := NewServer(ServerConfig{
				RuntimeDir:    dir,
				Logger:        srvA.logger,
				IdleTimeout:   10 * time.Minute,
				IdleCheckTick: 1 * time.Second,
			})
			bCtx, bCancel := context.WithCancel(context.Background())
			defer bCancel()
			_ = srv.ListenAndServe(bCtx)
			exited.Add(1)
		}()
	}

	// All should exit within 5 seconds
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		elapsed := time.Since(start)
		if exited.Load() != n {
			t.Fatalf("only %d/%d daemons exited", exited.Load(), n)
		}
		t.Logf("all %d competing daemons exited in %s", n, elapsed.Round(time.Millisecond))
	case <-time.After(10 * time.Second):
		t.Fatalf("only %d/%d daemons exited within 10s (orphans!)", exited.Load(), n)
	}

	// Verify daemon A still healthy
	conn, err := net.DialTimeout("unix", srvA.SocketPath(), 2*time.Second)
	if err != nil {
		t.Fatalf("daemon A not healthy: %v", err)
	}
	conn.Close()

	cancel()
	srvA.Shutdown()
}

// TestB2_SocketDeletion_DaemonExits verifies that when the socket file is
// deleted, the daemon detects this and exits gracefully within one idle
// check cycle.
func TestB2_SocketDeletion_DaemonExits(t *testing.T) {
	srv, _ := newTestServer(t, 10*time.Minute)
	// Use fast idle check for test speed
	srv.idleCheckTick = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForServerReady(t, srv.SocketPath())

	// Delete the socket file
	if err := os.Remove(srv.SocketPath()); err != nil {
		t.Fatalf("remove socket: %v", err)
	}

	// Daemon should detect and exit within a few ticks
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit after socket deletion within 5s")
	case err := <-errCh:
		// ListenAndServe returns nil on graceful shutdown
		if err != nil {
			t.Logf("daemon exited with: %v (acceptable if accept error)", err)
		} else {
			t.Log("daemon exited gracefully after socket deletion")
		}
	}
}

// TestB2_SocketReplaced_DaemonExits verifies that when the socket file is
// replaced by another daemon's socket, the original daemon detects the
// inode change and exits.
func TestB2_SocketReplaced_DaemonExits(t *testing.T) {
	srvA, dir := newTestServer(t, 10*time.Minute)
	srvA.idleCheckTick = 500 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srvA.ListenAndServe(ctx) }()
	waitForServerReady(t, srvA.SocketPath())

	// Delete socket and create a new one (simulating daemon B taking over)
	socketPath := srvA.SocketPath()
	os.Remove(socketPath)

	// Create a new listener on the same path (simulates daemon B)
	listenerB, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("bind replacement socket: %v", err)
	}
	defer listenerB.Close()

	// Daemon A should detect the inode change and exit
	select {
	case <-time.After(5 * time.Second):
		t.Fatal("daemon A did not exit after socket replacement within 5s")
	case err := <-errCh:
		if err != nil {
			t.Logf("daemon A exited with: %v", err)
		} else {
			t.Log("daemon A exited gracefully after socket replacement")
		}
	}

	// Verify daemon B's listener is still working
	conn, dialErr := net.DialTimeout("unix", socketPath, 2*time.Second)
	if dialErr != nil {
		t.Fatalf("daemon B's socket not connectable: %v", dialErr)
	}
	conn.Close()

	// Clean up
	_ = filepath.Join(dir, "nonce") // just reference dir to avoid unused warning
}
