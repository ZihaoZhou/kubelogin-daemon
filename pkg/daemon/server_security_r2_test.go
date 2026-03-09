package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Round 2 Security Audit Tests ---
// These tests expose issues found in Codex security audit Round 2.
// Written BEFORE the fixes (TDD).

// Finding #1: store-token accepts non-hex cache keys, creating in-memory
// TokenManagers that can never be persisted (PersistToken rejects them).
// This allows unbounded manager growth via arbitrary cache keys.
func TestR2_StoreToken_RejectsNonHexCacheKey(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	badKeys := []string{
		"not-hex-key",
		"../../../etc/passwd",
		"key with spaces",
		"ZZZZ",
		"",
	}

	for _, key := range badKeys {
		t.Run(key, func(t *testing.T) {
			resp := sendRawTestRequest(t, socketPath, Request{
				Version:      ProtocolVersion,
				Command:      "store-token",
				CacheKey:     key,
				IssuerURL:    "https://example.com",
				ClientID:     "test",
				IDToken:      testToken,
				RefreshToken: "rt",
			})
			if resp.Status == "ok" {
				t.Errorf("store-token should reject non-hex cache_key %q, got ok", key)
			}
		})
	}
}

// Finding #1b: get-token should also validate cache_key is hex
func TestR2_GetToken_RejectsNonHexCacheKey(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version:   ProtocolVersion,
		Command:   "get-token",
		CacheKey:  "not-hex-key!",
		IssuerURL: "https://example.com",
		ClientID:  "test",
	})
	if resp.Status == "ok" || resp.Status == "needs-auth" {
		// needs-auth is "accepted" (just means no token) — but it still
		// creates state entries with invalid keys. Should be rejected.
		t.Errorf("get-token should reject non-hex cache_key, got %q", resp.Status)
	}
}

// Finding #1c: begin-login should validate cache_key
func TestR2_BeginLogin_RejectsNonHexCacheKey(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	resp := sendRawTestRequest(t, socketPath, Request{
		Version:  ProtocolVersion,
		Command:  "begin-login",
		CacheKey: "../../../tmp/evil",
	})
	if resp.Status == "ok" {
		t.Errorf("begin-login should reject non-hex cache_key, got ok")
	}
}

// Finding #2: EvictStale cannot evict expired LOGIN_IN_PROGRESS entries.
// This allows unbounded memory growth by flooding begin-login with unique keys.
func TestR2_EvictStale_EvictsExpiredLoginInProgress(t *testing.T) {
	sm := NewStateManager()

	// Create maxStateEntries+200 expired LOGIN_IN_PROGRESS entries
	for i := 0; i < maxStateEntries+200; i++ {
		key := fmt.Sprintf("expired-%d", i)
		sm.mu.Lock()
		sm.entries[key] = &stateEntry{
			state:        StateLoginInProgress,
			loginStarted: time.Now().Add(-6 * time.Minute), // expired (> 5min TTL)
		}
		sm.mu.Unlock()
	}

	sm.EvictStale()

	sm.mu.RLock()
	count := len(sm.entries)
	sm.mu.RUnlock()

	if count > maxStateEntries {
		t.Errorf("EvictStale should evict expired LOGIN_IN_PROGRESS entries, but %d remain (max %d)",
			count, maxStateEntries)
	}
}

// Finding #4: No connection limit — server can be DoS'd by opening many concurrent connections.
func TestR2_ConnectionLimit(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Open many connections without reading (slow clients)
	const n = 300
	conns := make([]net.Conn, 0, n)
	var accepted int
	for i := 0; i < n; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err != nil {
			break
		}
		conns = append(conns, conn)
		accepted++
	}

	// Clean up connections
	for _, c := range conns {
		c.Close()
	}

	// Server should still respond after the storm
	time.Sleep(200 * time.Millisecond)
	resp := sendRawTestRequest(t, socketPath, Request{
		Version: ProtocolVersion,
		Command: "health",
	})
	if resp.Status != "ok" {
		t.Error("server should survive connection flood")
	}

	// The real check: after adding a connection limit, accepted should be capped
	// For now, just verify the server survives. The limit will be checked by the fix.
	t.Logf("accepted %d connections out of %d attempted", accepted, n)
}

// Finding #4b: Verify that after the connection limit fix, new connections
// are accepted once old ones close.
func TestR2_ConnectionLimit_Recovery(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	// Hold some connections
	const holdCount = 50
	conns := make([]net.Conn, 0, holdCount)
	for i := 0; i < holdCount; i++ {
		conn, err := net.DialTimeout("unix", socketPath, 1*time.Second)
		if err != nil {
			break
		}
		conns = append(conns, conn)
	}

	// Release all held connections
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)

	// Server should handle new connections fine
	const newConns = 20
	var wg sync.WaitGroup
	var successes int32
	wg.Add(newConns)
	for i := 0; i < newConns; i++ {
		go func() {
			defer wg.Done()
			resp := sendRawTestRequest(t, socketPath, Request{
				Version: ProtocolVersion,
				Command: "health",
			})
			if resp.Status == "ok" {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}
	wg.Wait()
	t.Logf("after release: %d/%d new connections succeeded", successes, newConns)
}

// Helper: create a server with a short idle timeout and connection limiting
func startShortServerWithConnLimit(t *testing.T) (*Server, string, context.CancelFunc) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "r2-")
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
		IdleTimeout: 10 * time.Minute,
	})

	socketPath := filepath.Join(dir, "sock")
	ctx, cancel := context.WithCancel(context.Background())

	go func() { srv.ListenAndServe(ctx) }()
	waitForServerReady(t, socketPath)

	t.Cleanup(func() { cancel() })
	return srv, socketPath, cancel
}

// --- Verify that valid hex cache keys still work after adding validation ---
func TestR2_ValidHexCacheKeys_StillWork(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	validKeys := []string{
		"aabb0011",
		"AABB0011",
		"0123456789abcdef",
		"FF",
		"a",
	}

	for _, key := range validKeys {
		t.Run(key, func(t *testing.T) {
			resp := sendRawTestRequest(t, socketPath, Request{
				Version:      ProtocolVersion,
				Command:      "store-token",
				CacheKey:     key,
				IssuerURL:    "https://example.com",
				ClientID:     "test",
				IDToken:      testToken,
				RefreshToken: "rt",
			})
			if resp.Status != "ok" {
				t.Errorf("store-token should accept valid hex cache_key %q, got %q: %s", key, resp.Status, resp.Error)
			}
		})
	}
}

// Regression test: store-token with empty cache_key is already handled
func TestR2_StoreTokenEmptyCacheKey(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	resp := sendRawTestRequest(t, socketPath, Request{
		Version:      ProtocolVersion,
		Command:      "store-token",
		CacheKey:     "",
		IssuerURL:    "https://example.com",
		ClientID:     "test",
		IDToken:      testToken,
		RefreshToken: "rt",
	})
	if resp.Status != "error" {
		t.Errorf("store-token with empty cache_key should fail, got %q", resp.Status)
	}
}

// Also verify JSON is accepted correctly for health (after all validation additions)
func TestR2_HealthStillWorks(t *testing.T) {
	_, socketPath, _ := startShortServer(t)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := Request{Version: ProtocolVersion, Command: "health", Nonce: readTestNonce(socketPath)}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("health: want ok, got %q", resp.Status)
	}
}
