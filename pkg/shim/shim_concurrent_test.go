package shim

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// startShortPathDaemon starts a daemon with a short socket path to avoid
// Unix socket path length limits (104 bytes on macOS).
// Returns the runtimeDir (shim functions derive the IPC address from it).
func startShortPathDaemon(t *testing.T) (string, func()) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "kld-")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	dir := filepath.Join(base, "rt")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logDir := filepath.Join(base, "log")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatalf("mkdir log: %v", err)
	}
	logger, err := daemon.NewLogger(logDir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	srv := daemon.NewServer(daemon.ServerConfig{
		RuntimeDir:  dir,
		Logger:      logger,
		IdleTimeout: 10 * time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.ListenAndServe(ctx)
		close(done)
	}()

	addr := daemon.TransportAddress(dir)
	for i := 0; i < 50; i++ {
		conn, err := daemon.TransportDial(addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cleanup := func() {
		cancel()
		<-done
		logger.Close()
		os.RemoveAll(base)
	}
	return dir, cleanup
}

// TestConcurrent100_SameDaemon verifies that 100 concurrent get-token
// requests to the SAME daemon all succeed. This test should PASS — the daemon's
// internal concurrency (atomic reads, singleflight, sync.Map) is solid.
//
// The real-world 100-concurrent failure was caused by TMPDIR divergence
// (each process found a different socket path and auto-started its own daemon),
// NOT by a daemon concurrency bug.
func TestConcurrent100_SameDaemon(t *testing.T) {
	runtimeDir, cleanup := startShortPathDaemon(t)
	defer cleanup()

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}

	// Store a token first
	storeResp, err := StoreToken(runtimeDir, "aa00bb00cc00dd00", req, testToken, "rt")
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}
	if storeResp.Status != "ok" {
		t.Fatalf("store: %s (error: %s)", storeResp.Status, storeResp.Error)
	}

	const n = 100
	var wg sync.WaitGroup
	var failures atomic.Int32

	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start // synchronized thundering-herd start
			resp, err := GetTokenFromDaemon(runtimeDir, "aa00bb00cc00dd00", req)
			if err != nil {
				failures.Add(1)
				t.Logf("[%d] error: %v", i, err)
				return
			}
			if resp.Status != "ok" {
				failures.Add(1)
				t.Logf("[%d] status=%s error=%s", i, resp.Status, resp.Error)
				return
			}
			if resp.Token != testToken {
				failures.Add(1)
				t.Logf("[%d] wrong token", i)
			}
		}()
	}
	close(start)
	wg.Wait()

	if f := failures.Load(); f > 0 {
		t.Errorf("%d/%d concurrent get-token calls failed (daemon internal concurrency broken)", f, n)
	}
}
