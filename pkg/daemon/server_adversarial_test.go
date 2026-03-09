package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// shortTestServer creates a test server with a shorter temp dir path
// to avoid exceeding the 104-char Unix socket path limit on macOS.
func shortTestServer(t *testing.T, idleTimeout time.Duration) (*Server, string) {
	t.Helper()
	// Use /tmp directly for short paths
	base, err := os.MkdirTemp("/tmp", "adv")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })

	dir := filepath.Join(base, "r")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logDir := filepath.Join(base, "l")
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

func sendRawTestRequest(t *testing.T, socketPath string, req Request) Response {
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

// readTestNonce reads the nonce from the runtime dir for test requests.
func readTestNonce(socketPath string) string {
	noncePath := filepath.Join(filepath.Dir(socketPath), "nonce")
	data, err := os.ReadFile(noncePath)
	if err != nil {
		return ""
	}
	return string(data)
}

func startShortServer(t *testing.T) (*Server, string, context.CancelFunc) {
	t.Helper()
	srv, dir := shortTestServer(t, 10*time.Minute)
	socketPath := filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	t.Cleanup(func() { cancel() })
	return srv, socketPath, cancel
}

// Attack vector: Send oversized payload (>1MB limit).
func TestAdv_SrvOversized(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send a request with a 2MB payload (exceeds 1MB limit)
	bigValue := strings.Repeat("A", 2<<20)
	req := fmt.Sprintf(`{"version":%d,"command":"get-token","cache_key":"%s"}`, ProtocolVersion, bigValue)
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Logf("write error (expected): %v", err)
		return
	}

	// Should get an error response or connection close
	var resp Response
	err = json.NewDecoder(conn).Decode(&resp)
	if err != nil {
		t.Logf("decode error (expected for oversized payload): %v", err)
		return
	}
	if resp.Status != "error" {
		t.Errorf("oversized payload: expected error status, got %q", resp.Status)
	}
	t.Logf("oversized payload response: %s", resp.Error)
}

// Attack vector: Malformed JSON payloads.
func TestAdv_SrvMalformed(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	malformedPayloads := []struct {
		name    string
		payload string
	}{
		{"empty", ""},
		{"brace", "{"},
		{"null", "null"},
		{"array", "[]"},
		{"number", "42"},
		{"string", `"hello"`},
		{"binary", "\x00\x01\x02\x03"},
		{"incomplete", `{"version":2,"command":"he`},
		{"trailing", `{"version":2,"command":"health"}EXTRA`},
	}

	for _, tc := range malformedPayloads {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = conn.Write([]byte(tc.payload))
			if err != nil {
				t.Logf("write error: %v", err)
				return
			}
			// Close write side to signal EOF
			if uc, ok := conn.(*net.UnixConn); ok {
				uc.CloseWrite()
			}

			var resp Response
			err = json.NewDecoder(conn).Decode(&resp)
			if err != nil {
				t.Logf("decode error (expected for malformed): %v", err)
				return
			}
			if resp.Status != "error" {
				t.Errorf("malformed JSON %q: expected error, got %q", tc.name, resp.Status)
			}
		})
	}

	// Server should still be alive after all the abuse
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive malformed JSON attacks")
	}
}

// Attack vector: Unknown JSON fields (DisallowUnknownFields is used).
func TestAdv_SrvUnknownFields(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send a request with an unknown field
	payload := fmt.Sprintf(`{"version":%d,"command":"health","unknown_evil_field":"pwned"}`, ProtocolVersion)
	conn.Write([]byte(payload + "\n"))

	var resp Response
	err = json.NewDecoder(conn).Decode(&resp)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "error" {
		t.Logf("FINDING: Server accepted request with unknown field (status=%q). DisallowUnknownFields may not reject extra fields.", resp.Status)
	} else {
		t.Logf("correctly rejected unknown field: %s", resp.Error)
	}
}

// Attack vector: Connection drop mid-request (partial write then close).
func TestAdv_SrvPartialWrite(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn.Write([]byte(`{"version":2,"co`))
		conn.Close()
	}

	// Server should survive
	time.Sleep(100 * time.Millisecond)
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive partial write attacks")
	}
}

// Attack vector: Rapid connect/disconnect without sending any data.
func TestAdv_SrvConnStorm(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
			if err != nil {
				return
			}
			conn.Close()
		}()
	}
	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive connect/disconnect storm")
	}
}

// Attack vector: Concurrent requests on different commands.
func TestAdv_SrvConcurrentMix(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Store a token first
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "aa0011",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	commands := []Request{
		{Version: ProtocolVersion, Command: "health"},
		{Version: ProtocolVersion, Command: "get-token", CacheKey: "aa0011", IssuerURL: "https://example.com", ClientID: "test"},
		{Version: ProtocolVersion, Command: "check", CacheKey: "aa0011"},
		{Version: ProtocolVersion, Command: "begin-login", CacheKey: "aa0022"},
		{Version: ProtocolVersion, Command: "cancel-login", CacheKey: "aa0022"},
		{Version: ProtocolVersion, Command: "check", CacheKey: "eeee0000"},
	}

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			req := commands[id%len(commands)]
			resp := sendRawTestRequest(t, socketPath, req)
			if resp.Version != ProtocolVersion {
				t.Errorf("goroutine %d: version mismatch, got %d", id, resp.Version)
			}
		}(g)
	}
	wg.Wait()
}

// Attack vector: get-token with empty cache_key.
func TestAdv_SrvGetTokenEmpty(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "get-token",
	})
	if resp.Status != "error" {
		t.Errorf("get-token with empty cache_key: want error, got %q", resp.Status)
	}
}

// Attack vector: store-token without id_token.
func TestAdv_SrvStoreMissing(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Missing id_token
	resp := sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "aabb0011",
		RefreshToken: "rt",
	})
	if resp.Status != "error" {
		t.Errorf("store-token without id_token: want error, got %q", resp.Status)
	}

	// Missing cache_key
	resp2 := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "store-token",
		IDToken: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig",
	})
	if resp2.Status != "error" {
		t.Errorf("store-token without cache_key: want error, got %q", resp2.Status)
	}
}

// Attack vector: store-token with an invalid JWT (can't parse expiry).
func TestAdv_SrvStoreInvalidJWT(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"notjwt", "not-a-jwt-token"},
		{"1seg", "eyJhbGciOiJSUzI1NiJ9"},
		{"2seg", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0"},
		{"badB64", "eyJ!!!.eyJ!!!.sig"},
		{"noExp", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"},
	}

	for _, tc := range invalidTokens {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendRawTestRequest(t, socketPath, Request{
				Version:      ProtocolVersion,
				Command:      "store-token",
				CacheKey:     "aabb0022",
				IssuerURL:    "https://example.com",
				ClientID:     "test",
				IDToken:      tc.token,
				RefreshToken: "rt",
			})
			if resp.Status == "ok" {
				t.Logf("FINDING: store-token accepted invalid JWT %q", tc.name)
			}
		})
	}
}

// Attack vector: Multiple shutdown commands.
func TestAdv_SrvDoubleShutdown(t *testing.T) {
	srv, socketPath, _ := startShortServer(t)

	// First shutdown
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "shutdown",
	})
	if resp.Status != "ok" {
		t.Errorf("first shutdown: want ok, got %q", resp.Status)
	}

	// Direct call to Shutdown (should be safe via shutdownOnce)
	srv.Shutdown()
	srv.Shutdown()
}

// Attack vector: Requests after shutdown is initiated.
func TestAdv_SrvReqDuringShutdown(t *testing.T) {
	srv, socketPath, _ := startShortServer(t)

	go srv.Shutdown()

	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
		if err != nil {
			break
		}
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		req := Request{Version: ProtocolVersion, Command: "health"}
		json.NewEncoder(conn).Encode(req)
		var resp Response
		json.NewDecoder(conn).Decode(&resp)
		conn.Close()
	}
}

// Attack vector: Slow client that holds connection.
func TestAdv_SrvSlowClient(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Connect but don't send anything
	slowConn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer slowConn.Close()

	// Other connections still work
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("slow client should not block other connections")
	}
}

// Attack vector: Multiple JSON objects in one connection (pipeline attack).
func TestAdv_SrvPipelined(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send two JSON objects back-to-back — server should reject trailing data
	req1 := fmt.Sprintf(`{"version":%d,"command":"health"}`, ProtocolVersion)
	req2 := fmt.Sprintf(`{"version":%d,"command":"health"}`, ProtocolVersion)
	conn.Write([]byte(req1 + "\n" + req2 + "\n"))

	// Server should reject the pipelined request (trailing data detection)
	var resp1 Response
	err = json.NewDecoder(conn).Decode(&resp1)
	if err != nil {
		t.Fatalf("first decode: %v", err)
	}
	if resp1.Status != "error" {
		t.Errorf("pipelined request should be rejected with error, got %q", resp1.Status)
	}
	if resp1.Error == "" || !strings.Contains(resp1.Error, "trailing") {
		t.Logf("response error: %q (expected trailing data rejection)", resp1.Error)
	}
}

// Attack vector: Send request with future protocol version.
func TestAdv_SrvFutureVersion(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion + 1,
		Command: "health",
	})
	if resp.Status != "error" {
		t.Errorf("future protocol version: want error, got %q", resp.Status)
	}
}

// Attack vector: Send request with version 0.
func TestAdv_SrvV0(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: 0,
		Command: "health",
	})
	if resp.Status != "error" {
		t.Errorf("version 0: want error, got %q", resp.Status)
	}
}

// Attack vector: Negative protocol version.
func TestAdv_SrvVNeg(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: -1,
		Command: "health",
	})
	if resp.Status != "error" {
		t.Errorf("negative version: want error, got %q", resp.Status)
	}
}

// Attack vector: Write response to a connection that was already closed.
func TestAdv_SrvClosedConn(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		req := Request{Version: ProtocolVersion, Command: "health"}
		json.NewEncoder(conn).Encode(req)
		conn.Close()
	}

	time.Sleep(200 * time.Millisecond)
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive writes to closed connections")
	}
}

// Attack vector: Send a huge number of concurrent requests.
func TestAdv_SrvFlood(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))

			req := Request{Version: ProtocolVersion, Command: "health"}
			json.NewEncoder(conn).Encode(req)

			var resp Response
			json.NewDecoder(conn).Decode(&resp)
		}()
	}
	wg.Wait()

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive connection flood")
	}
}

// Attack vector: Deeply nested extra_params.
func TestAdv_SrvDeepNesting(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	nesting := 1000
	payload := strings.Repeat(`{"extra_params":`, nesting) + `{}` + strings.Repeat(`}`, nesting)
	conn.Write([]byte(payload + "\n"))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Logf("deep nesting response: %s", string(buf[:n]))
	}
}

// Attack vector: VerifyPeerUID should work for same-UID connection.
func TestAdv_SrvPeerUID(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Errorf("same-UID connection should succeed, got %q", resp.Status)
	}
}

// Attack vector: symlink at runtimeDir path.
func TestAdv_SrvSymlinkDir(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "adv")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	defer os.RemoveAll(base)

	realDir := filepath.Join(base, "real")
	os.MkdirAll(realDir, 0700)
	symlinkDir := filepath.Join(base, "sym")
	os.Symlink(realDir, symlinkDir)

	logDir := filepath.Join(base, "l")
	os.MkdirAll(logDir, 0700)
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer logger.Close()

	srv := NewServer(ServerConfig{
		RuntimeDir:  symlinkDir,
		Logger:      logger,
		IdleTimeout: 10 * time.Minute,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = srv.ListenAndServe(ctx)
	if err == nil {
		t.Error("VULNERABILITY: ListenAndServe should reject symlinked runtime dir")
		srv.Shutdown()
	} else {
		t.Logf("correctly rejected symlinked runtime dir: %v", err)
	}
}

// Attack vector: Half-close connection.
func TestAdv_SrvHalfClose(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := Request{Version: ProtocolVersion, Command: "health", Nonce: readTestNonce(socketPath)}
	json.NewEncoder(conn).Encode(req)

	if uc, ok := conn.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	var resp Response
	err = json.NewDecoder(conn).Decode(&resp)
	if err != nil {
		t.Logf("half-close decode error: %v", err)
	} else if resp.Status != "ok" {
		t.Errorf("half-close: want ok, got %q", resp.Status)
	}
}

// Attack vector: Slow reader.
func TestAdv_SrvSlowReader(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	req := Request{Version: ProtocolVersion, Command: "health", Nonce: readTestNonce(socketPath)}
	json.NewEncoder(conn).Encode(req)

	// Read one byte at a time
	var buf []byte
	for {
		b := make([]byte, 1)
		n, err := conn.Read(b)
		if n > 0 {
			buf = append(buf, b[:n]...)
		}
		if err == io.EOF || err != nil {
			break
		}
		if len(buf) > 0 && buf[len(buf)-1] == '\n' {
			break
		}
	}

	if len(buf) > 0 {
		var resp Response
		if err := json.Unmarshal(buf, &resp); err != nil {
			t.Logf("slow read unmarshal: %v", err)
		} else if resp.Status != "ok" {
			t.Errorf("slow read: want ok, got %q", resp.Status)
		}
	}
}

// Attack vector: Very short idle timeout.
func TestAdv_SrvShortIdle(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "adv")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	defer os.RemoveAll(base)

	dir := filepath.Join(base, "r")
	os.MkdirAll(dir, 0700)
	logDir := filepath.Join(base, "l")
	os.MkdirAll(logDir, 0700)
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	srv := NewServer(ServerConfig{
		RuntimeDir:    dir,
		Logger:        logger,
		IdleTimeout:   1 * time.Millisecond,
		IdleCheckTick: 10 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("exit error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server should have auto-exited with 1ms idle timeout")
		cancel()
	}
}

// Attack vector: check command with empty cache key.
func TestAdv_SrvCheckEmpty(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "check",
	})

	if resp.Status != "ok" {
		t.Errorf("check with empty cache_key: want ok, got %q", resp.Status)
	}
	if resp.DaemonRunning == nil || !*resp.DaemonRunning {
		t.Error("daemon should report as running")
	}
}

// Attack vector: begin-login with empty cache key.
func TestAdv_SrvBeginEmpty(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "begin-login",
	})
	if resp.Status != "error" {
		t.Errorf("begin-login with empty cache_key: want error, got %q", resp.Status)
	}
}

// Attack vector: cancel-login with empty cache key.
func TestAdv_SrvCancelEmpty(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "cancel-login",
	})
	if resp.Status != "error" {
		t.Errorf("cancel-login with empty cache_key: want error, got %q", resp.Status)
	}
}

// Attack vector: refresh with empty cache key.
func TestAdv_SrvRefreshEmpty(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "refresh",
	})
	if resp.Status != "error" {
		t.Errorf("refresh with empty cache_key: want error, got %q", resp.Status)
	}
}

// Attack vector: store-token with a JWT that has exp in the past.
func TestAdv_SrvStoreExpired(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// This JWT has exp=1 (January 1, 1970)
	expiredToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.sig"

	resp := sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "aabb0033",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      expiredToken,
		RefreshToken: "rt",
	})

	if resp.Status == "ok" {
		t.Log("FINDING: store-token accepts already-expired JWT tokens. Subsequent get-token will immediately try to refresh.")
	}

	// Now get-token should try to refresh (and fail since no real OIDC provider)
	getResp := sendRawTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "aabb0033",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if getResp.Status == "ok" {
		t.Error("get-token with expired stored token should not return ok")
	}
}

// Attack vector: store-token with non-hex cache key.
func TestAdv_SrvStoreNonHexKey(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	resp := sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "not-hex-key!@#$",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// After Round 2 fix: server validates cache_key format before creating
	// a TokenManager, preventing unbounded in-memory growth.
	if resp.Status != "error" {
		t.Errorf("store-token should reject non-hex cache key, got %q", resp.Status)
	}
}

// Attack vector: get-token then begin-login then get-token — should block during login.
func TestAdv_SrvLoginBlocks(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Begin login
	resp := sendRawTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "b10c0001",
	})
	if resp.Status != "ok" {
		t.Fatalf("begin-login: %q", resp.Status)
	}

	// get-token should return login-in-progress
	getResp := sendRawTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "b10c0001",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if getResp.Status != "login-in-progress" {
		t.Errorf("get-token during login: want login-in-progress, got %q", getResp.Status)
	}

	// Store token (completes login)
	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "b10c0001",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})

	// get-token should now work
	getResp2 := sendRawTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "b10c0001",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if getResp2.Status != "ok" {
		t.Errorf("get-token after login: want ok, got %q (error: %s)", getResp2.Status, getResp2.Error)
	}
}
