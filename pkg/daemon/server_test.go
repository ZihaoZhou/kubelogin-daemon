package daemon

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestServer(t *testing.T, idleTimeout time.Duration) (*Server, string) {
	t.Helper()
	// Use os.MkdirTemp with a short prefix instead of t.TempDir() to avoid
	// exceeding macOS's 104-byte Unix socket path limit. t.TempDir() embeds
	// the full test name in the path (e.g., /var/folders/.../TestName.../001/),
	// which easily exceeds 104 bytes for longer test names.
	base, err := os.MkdirTemp("", "kld")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	// Use a short subdir name and ensure 0700 permissions
	dir := filepath.Join(base, "rt")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logDir := filepath.Join(base, "log")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatalf("mkdir log: %v", err)
	}
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	srv := NewServer(ServerConfig{
		RuntimeDir:  dir,
		Logger:      logger,
		IdleTimeout: idleTimeout,
	})
	return srv, dir
}

func waitForServerReady(t *testing.T, socketPath string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server not ready at %s after 2.5s", socketPath)
}

func sendTestRequest(t *testing.T, socketPath string, req Request) Response {
	t.Helper()

	// SEC-CRIT-1: Read nonce from runtime dir (required for all requests).
	noncePath := filepath.Join(filepath.Dir(socketPath), "nonce")
	if data, err := os.ReadFile(noncePath); err == nil {
		req.Nonce = string(data)
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestServer_HealthCheck(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	resp := sendTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})

	if resp.Status != "ok" {
		t.Errorf("want status ok, got %q", resp.Status)
	}
	if resp.Uptime == "" {
		t.Error("uptime should not be empty")
	}
	if resp.DaemonVersion != ProtocolVersion {
		t.Errorf("want daemon_version %d, got %d", ProtocolVersion, resp.DaemonVersion)
	}

	cancel()
}

func TestServer_VersionMismatch(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	resp := sendTestRequest(t, socketPath, Request{
		Version: 999, // bad version
		Command: "health",
	})

	if resp.Status != "error" {
		t.Errorf("want status error for version mismatch, got %q", resp.Status)
	}

	cancel()
}

func TestServer_GetTokenNeedsAuth(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "get-token",
		CacheKey: "aabbccdd",
	})

	if resp.Status != "needs-auth" {
		t.Errorf("want needs-auth for unknown cache key, got %q", resp.Status)
	}

	cancel()
}

func TestServer_StoreAndGetToken(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// A valid JWT-like token with exp claim (expires in year 2033)
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	// Store a token
	storeResp := sendTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "abcdef01",
		IssuerURL:    "https://example.com",
		ClientID:     "test-client",
		IDToken:      testToken,
		RefreshToken: "test-refresh",
	})

	if storeResp.Status != "ok" {
		t.Fatalf("store: want ok, got %q (error: %s)", storeResp.Status, storeResp.Error)
	}

	// Get the token back
	getResp := sendTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "abcdef01",
		IssuerURL: "https://example.com",
		ClientID:  "test-client",
	})

	if getResp.Status != "ok" {
		t.Fatalf("get: want ok, got %q (error: %s)", getResp.Status, getResp.Error)
	}
	if getResp.Token != testToken {
		t.Errorf("want token %q, got %q", testToken, getResp.Token)
	}

	// Verify it was persisted to disk
	gotID, gotRT, err := LoadPersistedToken(dir, "abcdef01")
	if err != nil {
		t.Fatalf("load persisted: %v", err)
	}
	if gotID != testToken {
		t.Errorf("persisted id: want test token, got %q", gotID)
	}
	if gotRT != "test-refresh" {
		t.Errorf("persisted rt: want test-refresh, got %q", gotRT)
	}

	cancel()
}

func TestServer_ConcurrentGetToken(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Store a token first
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "cc001122",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// 50 concurrent get-token requests
	const n = 50
	var wg sync.WaitGroup
	var failures int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp := sendTestRequest(t, socketPath, Request{
				Version:   ProtocolVersion,
				Command:   "get-token",
				CacheKey:  "cc001122",
				IssuerURL: "https://example.com",
				ClientID:  "test",
			})
			if resp.Status != "ok" || resp.Token != testToken {
				t.Errorf("concurrent get: want ok with token, got status=%q token=%q", resp.Status, resp.Token)
			}
		}()
	}
	wg.Wait()

	if failures > 0 {
		t.Errorf("%d/%d concurrent requests failed", failures, n)
	}

	cancel()
}

func TestServer_Shutdown(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Send shutdown
	resp := sendTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "shutdown",
	})
	if resp.Status != "ok" {
		t.Errorf("shutdown: want ok, got %q", resp.Status)
	}

	// Server should exit
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error after shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server did not exit after shutdown")
	}

	// Socket file should be cleaned up
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after shutdown")
	}
}

// TestServer_ShutdownFast verifies that Shutdown() completes in <200ms even
// when connections with 30-second deadlines are active.
func TestServer_ShutdownFast(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Open 5 connections that block (read nonce, connect, but don't send a full request).
	// These connections have 30-second deadlines set by handleConnection.
	noncePath := filepath.Join(dir, "nonce")
	nonceData, err := os.ReadFile(noncePath)
	if err != nil {
		t.Fatalf("read nonce: %v", err)
	}
	_ = nonceData

	var conns []net.Conn
	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	// Give handleConnection goroutines time to start and set their 30s deadlines.
	time.Sleep(50 * time.Millisecond)

	// Shutdown should complete in <200ms, not 30 seconds.
	start := time.Now()
	srv.Shutdown()
	elapsed := time.Since(start)

	if elapsed > 200*time.Millisecond {
		t.Fatalf("Shutdown() took %s (want <200ms)", elapsed)
	}
	t.Logf("Shutdown() completed in %s", elapsed.Round(time.Millisecond))
}

// TestServer_ShutdownInterruptsActiveConn verifies that a connection in the
// middle of processing receives an error when Shutdown() is called.
func TestServer_ShutdownInterruptsActiveConn(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Connect and send a valid request header to start the handler.
	noncePath := filepath.Join(dir, "nonce")
	nonceData, err := os.ReadFile(noncePath)
	if err != nil {
		t.Fatalf("read nonce: %v", err)
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a valid request that will take time to process (get-token with
	// a valid-format cache key that has no token manager → needs-auth response).
	req := Request{
		Version:  ProtocolVersion,
		Nonce:    string(nonceData),
		Command:  "get-token",
		CacheKey: "aa11bb22cc33dd44ee55ff0011223344aa11bb22cc33dd44ee55ff0011223344",
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Read response (should succeed — this request completes fast)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Now open a new connection that will be mid-read when we shutdown.
	conn2, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial2: %v", err)
	}
	defer conn2.Close()

	// Don't send anything — handler is blocked on json.Decode with 30s deadline.
	time.Sleep(50 * time.Millisecond)

	// Trigger shutdown
	srv.Shutdown()

	// The blocked connection should get an error (connection closed).
	conn2.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn2.Read(buf)
	if readErr == nil {
		t.Error("expected error on connection after shutdown, got nil")
	}
	t.Logf("connection correctly received error after shutdown: %v", readErr)
}

func TestServer_IdleTimeout(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "rt")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logDir := filepath.Join(base, "log")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		t.Fatalf("mkdir log: %v", err)
	}
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	srv := NewServer(ServerConfig{
		RuntimeDir:    dir,
		Logger:        logger,
		IdleTimeout:   200 * time.Millisecond,
		IdleCheckTick: 100 * time.Millisecond, // fast tick for testing
	})
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Verify server is running
	resp := sendTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Fatalf("health check failed: %q", resp.Status)
	}

	// Wait for idle timeout to auto-exit (200ms idle + 100ms tick = should exit within 500ms)
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("unexpected error on idle exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server did not auto-exit after idle timeout")
	}

	// Socket file should be cleaned up
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after idle exit")
	}
}

func TestServer_SocketPermissions(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Verify socket file permissions
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	// Socket permissions should be 0600
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("want socket perms 0600, got %o", perm)
	}

	// Verify runtime directory permissions
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("runtime dir has insecure permissions: %o", perm)
	}

	cancel()
}

func TestServer_NoFileLocksUsed(t *testing.T) {
	// This test verifies that no flock or lockfile mechanisms are used.
	// It's a compile-time guarantee enforced by not importing flock packages,
	// but we verify at runtime that the daemon directory has no .lock files.
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Store and get a token
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "ee990011",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// Check no .lock files were created
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".lock" {
			t.Errorf("lock file created: %s (violates zero-lock design)", e.Name())
		}
	}

	cancel()
}

func TestServer_BeginAndCancelLogin(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Begin login
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "aabb0011",
	})
	if resp.Status != "ok" {
		t.Fatalf("begin-login: want ok, got %q (error: %s)", resp.Status, resp.Error)
	}

	// Second begin-login should return login-in-progress
	resp2 := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "aabb0011",
	})
	if resp2.Status != "login-in-progress" {
		t.Errorf("second begin-login: want login-in-progress, got %q", resp2.Status)
	}
	if resp2.LoginStartedAt == nil {
		t.Error("should include login_started_at")
	}

	// get-token should return LOGIN_IN_PROGRESS
	resp3 := sendTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "aabb0011",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if resp3.Status != "login-in-progress" {
		t.Errorf("get-token during login: want login-in-progress, got %q", resp3.Status)
	}
	if resp3.ErrorCode != ErrCodeLoginInProgress {
		t.Errorf("want error code LOGIN_IN_PROGRESS, got %q", resp3.ErrorCode)
	}

	// Cancel login
	resp4 := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "cancel-login",
		CacheKey: "aabb0011",
	})
	if resp4.Status != "ok" {
		t.Errorf("cancel-login: want ok, got %q", resp4.Status)
	}

	// get-token should now return needs-auth (not login-in-progress)
	resp5 := sendTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "aabb0011",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if resp5.Status == "login-in-progress" {
		t.Error("get-token after cancel should not be login-in-progress")
	}

	cancel()
}

func TestServer_CheckCommand(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Check with no token — should return NEEDS_LOGIN
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0022",
	})
	if resp.Ready != nil && *resp.Ready {
		t.Error("check without token should not be ready")
	}
	if resp.State != string(StateNeedsLogin) {
		t.Errorf("check state: want NEEDS_LOGIN, got %q", resp.State)
	}
	if resp.DaemonRunning == nil || !*resp.DaemonRunning {
		t.Error("daemon should be running")
	}

	// Store a token
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "aabb0022",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// Check with valid token — should be ready
	resp2 := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0022",
	})
	if resp2.Ready == nil || !*resp2.Ready {
		t.Error("check with valid token should be ready")
	}
	if resp2.State != string(StateValid) {
		t.Errorf("check state: want VALID, got %q", resp2.State)
	}
	if resp2.AccessTokenExpiry == nil {
		t.Error("should include access_token_expires")
	}
	if resp2.RefreshTokenValid == nil || !*resp2.RefreshTokenValid {
		t.Error("refresh_token_valid should be true")
	}

	cancel()
}

func TestServer_CheckDuringLogin(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Begin login
	sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "aabb0033",
	})

	// Check should show LOGIN_IN_PROGRESS
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0033",
	})
	if resp.State != string(StateLoginInProgress) {
		t.Errorf("check during login: want LOGIN_IN_PROGRESS, got %q", resp.State)
	}
	if resp.LoginStartedAt == nil {
		t.Error("should include login_started_at during login")
	}

	cancel()
}

func TestServer_StoreCompleteLogin(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Begin login
	sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "aabb0044",
	})

	// Store token
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "aabb0044",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// Check should now show VALID (login completed by store-token)
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0044",
	})
	if resp.State != string(StateValid) {
		t.Errorf("after store-token: want VALID, got %q", resp.State)
	}
	if resp.Ready == nil || !*resp.Ready {
		t.Error("should be ready after store-token")
	}

	cancel()
}

func TestServer_UnknownCommand(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Send unknown command — should return error, not panic
	resp := sendTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "foobar",
	})
	if resp.Status != "error" {
		t.Errorf("unknown command: want error, got %q", resp.Status)
	}

	// Daemon should still be alive
	resp2 := sendTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp2.Status != "ok" {
		t.Error("daemon should still be alive after unknown command")
	}

	cancel()
}

// TestServer_CheckWithPersistFile_ValidToken tests Bug 1.1: handleCheck reads
// persist files when no TokenManager is loaded (fresh daemon after restart).
func TestServer_CheckWithPersistFile_ValidToken(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	// Write a persist file directly (simulating a daemon restart where
	// persist files exist but no TokenManagers are loaded).
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	if err := PersistToken(dir, "aabb0044", testToken, "refresh-tok"); err != nil {
		t.Fatalf("PersistToken: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Check should see the persist file and report VALID (not NEEDS_LOGIN).
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0044",
	})
	if resp.Ready == nil || !*resp.Ready {
		t.Error("check with valid persist file should be ready")
	}
	if resp.State != string(StateValid) {
		t.Errorf("check state: want VALID, got %q", resp.State)
	}
	if resp.AccessTokenExpiry == nil {
		t.Error("should include access_token_expires")
	}

	cancel()
}

// TestServer_CheckWithPersistFile_ExpiredNeedsRefresh tests Bug 1.1: handleCheck
// returns NEEDS_REFRESH (not NEEDS_LOGIN) for expired token with valid refresh.
func TestServer_CheckWithPersistFile_ExpiredNeedsRefresh(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	// Write a persist file with an expired token but valid refresh token.
	expiredToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxMDAwMDAwMDAwfQ.sig"
	if err := PersistToken(dir, "aabb0055", expiredToken, "refresh-tok"); err != nil {
		t.Fatalf("PersistToken: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Check should see expired token + refresh token and report NEEDS_REFRESH.
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0055",
	})
	if resp.Ready != nil && *resp.Ready {
		t.Error("check with expired token should not be ready")
	}
	if resp.State != "NEEDS_REFRESH" {
		t.Errorf("check state: want NEEDS_REFRESH, got %q", resp.State)
	}

	cancel()
}

// TestServer_CheckWithPersistFile_EmptyToken tests Bug 1.1+1.2: handleCheck
// with an empty-token persist file (from watchdog bug) should report NEEDS_LOGIN.
func TestServer_CheckWithPersistFile_EmptyToken(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	// Write an empty-token persist file (the bug the watchdog guard prevents).
	if err := PersistToken(dir, "aabb0066", "", ""); err != nil {
		t.Fatalf("PersistToken: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Check should fall through to NEEDS_LOGIN since both tokens are empty.
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0066",
	})
	if resp.State != string(StateNeedsLogin) {
		t.Errorf("check state: want NEEDS_LOGIN for empty persist file, got %q", resp.State)
	}

	cancel()
}

// TestServer_CheckWithPersistFile_CorruptFile tests handleCheck falls through
// to NEEDS_LOGIN when the persist file contains invalid JSON.
func TestServer_CheckWithPersistFile_CorruptFile(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	// Write corrupt data directly to the persist file location.
	corruptPath := filepath.Join(dir, "aabb0077.json")
	if err := os.WriteFile(corruptPath, []byte("this is not json"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Check should fall through to NEEDS_LOGIN (corrupt file gets deleted by LoadPersistedToken).
	resp := sendTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "check",
		CacheKey: "aabb0077",
	})
	if resp.State != string(StateNeedsLogin) {
		t.Errorf("check state: want NEEDS_LOGIN for corrupt persist file, got %q", resp.State)
	}

	cancel()
}

// TestServer_NonceRejection tests that requests with incorrect nonce are rejected.
func TestServer_NonceRejection(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Send a request with a wrong nonce.
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := Request{
		Version: ProtocolVersion,
		Command: "health",
		Nonce:   "wrong-nonce-value",
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("wrong nonce should be rejected, got status %q", resp.Status)
	}

	cancel()
}

// TestServer_VersionMismatchIncludesPID tests that the version-mismatch error
// response includes PID so the shim can kill the old daemon.
func TestServer_VersionMismatchIncludesPID(t *testing.T) {
	srv, dir := newTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	// Read nonce for auth
	noncePath := filepath.Join(dir, "nonce")
	nonce, err := os.ReadFile(noncePath)
	if err != nil {
		t.Fatalf("read nonce: %v", err)
	}

	// Send request with wrong protocol version.
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := Request{
		Version: ProtocolVersion + 999, // definitely wrong
		Command: "health",
		Nonce:   string(nonce),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Errorf("version mismatch should return error, got %q", resp.Status)
	}
	if resp.PID <= 0 {
		t.Errorf("version mismatch response should include PID, got %d", resp.PID)
	}

	cancel()
}
