package shim

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// startTestDaemon starts a daemon server in the background for testing.
// Returns the runtimeDir (shim functions derive the IPC address from it).
func startTestDaemon(t *testing.T) (string, func()) {
	t.Helper()
	base := t.TempDir()
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
	}
	return dir, cleanup
}

func TestGetTokenFromDaemon_NeedsAuth(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}

	resp, err := GetTokenFromDaemon(runtimeDir, "aabb0011", req)
	if err != nil {
		t.Fatalf("GetTokenFromDaemon: %v", err)
	}
	if resp.Status != "needs-auth" {
		t.Errorf("want needs-auth, got %q", resp.Status)
	}
}

func TestStoreToken_AndGetBack(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}

	// Store
	storeResp, err := StoreToken(runtimeDir, "aabb0011", req, testToken, "test-rt")
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}
	if storeResp.Status != "ok" {
		t.Fatalf("store: want ok, got %q (error: %s)", storeResp.Status, storeResp.Error)
	}

	// Get back
	getResp, err := GetTokenFromDaemon(runtimeDir, "aabb0011", req)
	if err != nil {
		t.Fatalf("GetTokenFromDaemon: %v", err)
	}
	if getResp.Status != "ok" {
		t.Fatalf("get: want ok, got %q (error: %s)", getResp.Status, getResp.Error)
	}
	if getResp.Token != testToken {
		t.Errorf("want token %q, got %q", testToken, getResp.Token)
	}
}

func TestSendHealth(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	resp, err := SendHealth(runtimeDir)
	if err != nil {
		t.Fatalf("SendHealth: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("want ok, got %q", resp.Status)
	}
	if resp.Uptime == "" {
		t.Error("uptime should not be empty")
	}
}

func TestSendShutdown(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	err := SendShutdown(runtimeDir)
	if err != nil {
		t.Errorf("SendShutdown: %v", err)
	}

	// After shutdown, health check should fail
	time.Sleep(200 * time.Millisecond)
	_, err = SendHealth(runtimeDir)
	if err == nil {
		t.Error("health check should fail after shutdown")
	}
}

func TestStartupStorm_25Goroutines(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	// Store a token first
	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}
	_, err := StoreToken(runtimeDir, "ccdd2233", req, testToken, "rt")
	if err != nil {
		t.Fatalf("StoreToken: %v", err)
	}

	// 25 concurrent goroutines hitting get-token simultaneously
	const n = 25
	var wg sync.WaitGroup
	var failures atomic.Int32
	results := make([]string, n)

	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start // synchronized start
			resp, err := GetTokenFromDaemon(runtimeDir, "ccdd2233", req)
			if err != nil {
				failures.Add(1)
				t.Logf("goroutine %d: %v", i, err)
				return
			}
			if resp.Status != "ok" {
				failures.Add(1)
				t.Logf("goroutine %d: status=%s error=%s", i, resp.Status, resp.Error)
				return
			}
			results[i] = resp.Token
		}()
	}
	close(start)
	wg.Wait()

	if f := failures.Load(); f > 0 {
		t.Errorf("%d/%d startup storm goroutines failed", f, n)
	}

	// All successful goroutines should have received the same token
	for i, tok := range results {
		if tok != "" && tok != testToken {
			t.Errorf("goroutine %d: want %q, got %q", i, testToken, tok)
		}
	}
}

func TestVersionMismatch_FakeDaemon(t *testing.T) {
	// Start a fake daemon that responds with wrong protocol version.
	// Verify the shim detects the mismatch via the response fields.
	// Note: We can't test the full auto-restart flow in unit tests
	// because AutoStartDaemon forks os.Executable() (the test binary).
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var req daemon.Request
			json.NewDecoder(conn).Decode(&req)
			resp := daemon.Response{
				Version:       999,
				DaemonVersion: 999,
				Status:        "error",
				Error:         "unsupported protocol version",
			}
			json.NewEncoder(conn).Encode(resp)
			conn.Close()
		}
	}()

	// Test sendRequest directly to verify version mismatch detection.
	// sendRequest takes runtimeDir; TransportAddress(dir) returns dir/sock.
	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "get-token",
	}
	resp, err := sendRequest(dir, req)
	if err != nil {
		t.Fatalf("sendRequest: %v", err)
	}

	// The response should have a different daemon version
	if resp.DaemonVersion == daemon.ProtocolVersion {
		t.Error("fake daemon should return different protocol version")
	}
	if resp.Status != "error" {
		t.Errorf("want error status, got %q", resp.Status)
	}
}

func TestMultipleProviders(t *testing.T) {
	runtimeDir, cleanup := startTestDaemon(t)
	defer cleanup()

	token1 := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTk5OTk5OTk5OX0.sig"
	token2 := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMiIsImV4cCI6MTk5OTk5OTk5OX0.sig"

	req1 := daemon.Request{IssuerURL: "https://idp1.example.com", ClientID: "client1"}
	req2 := daemon.Request{IssuerURL: "https://idp2.example.com", ClientID: "client2"}

	// Store tokens for two different providers
	_, err := StoreToken(runtimeDir, "eeff4455", req1, token1, "rt1")
	if err != nil {
		t.Fatalf("store1: %v", err)
	}
	_, err = StoreToken(runtimeDir, "aabb6677", req2, token2, "rt2")
	if err != nil {
		t.Fatalf("store2: %v", err)
	}

	// Get them back — should be independent
	resp1, err := GetTokenFromDaemon(runtimeDir, "eeff4455", req1)
	if err != nil {
		t.Fatalf("get1: %v", err)
	}
	if resp1.Token != token1 {
		t.Errorf("provider1: want %q, got %q", token1, resp1.Token)
	}

	resp2, err := GetTokenFromDaemon(runtimeDir, "aabb6677", req2)
	if err != nil {
		t.Fatalf("get2: %v", err)
	}
	if resp2.Token != token2 {
		t.Errorf("provider2: want %q, got %q", token2, resp2.Token)
	}
}
