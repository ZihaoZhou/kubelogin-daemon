package shim

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// shortStartTestDaemon uses /tmp for short paths (macOS Unix socket path limit).
// Returns runtimeDir.
func shortStartTestDaemon(t *testing.T) (string, func()) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "adv")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	dir := filepath.Join(base, "r")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	logDir := filepath.Join(base, "l")
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

// shortRuntimeDir creates a short temp dir for fake servers.
// Returns runtimeDir. The fake server should listen at runtimeDir/sock.
func shortRuntimeDir(t *testing.T) (string, func()) {
	t.Helper()
	base, err := os.MkdirTemp("/tmp", "adv")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	cleanup := func() { os.RemoveAll(base) }
	return base, cleanup
}

// Attack vector: sendRequestWithTimeout with zero timeout.
func TestAdv_ShimZeroTimeout(t *testing.T) {
	runtimeDir, cleanup := shortStartTestDaemon(t)
	defer cleanup()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err := sendRequestWithTimeout(runtimeDir, req, 0)
	if err == nil {
		t.Error("zero timeout should fail")
	}
}

// Attack vector: sendRequestWithTimeout with negative timeout.
func TestAdv_ShimNegTimeout(t *testing.T) {
	runtimeDir, cleanup := shortStartTestDaemon(t)
	defer cleanup()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err := sendRequestWithTimeout(runtimeDir, req, -1*time.Second)
	if err == nil {
		t.Error("negative timeout should fail")
	}
}

// Attack vector: sendRequestWithTimeout with very small timeout.
func TestAdv_ShimTinyTimeout(t *testing.T) {
	runtimeDir, cleanup := shortStartTestDaemon(t)
	defer cleanup()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err := sendRequestWithTimeout(runtimeDir, req, 1*time.Nanosecond)
	if err != nil {
		t.Logf("1ns timeout correctly failed: %v", err)
	} else {
		t.Log("1ns timeout surprisingly succeeded (fast local socket)")
	}
}

// Attack vector: sendRequest to nonexistent runtime dir.
func TestAdv_ShimNoSocket(t *testing.T) {
	_, err := sendRequest(filepath.Join(t.TempDir(), "no-such-dir"), daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	})
	if err == nil {
		t.Error("nonexistent runtime dir should fail")
	}
}

// Attack vector: GetTokenFromDaemon with nonexistent daemon.
func TestAdv_ShimAutoStart(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}
	_, err := GetTokenFromDaemon(runtimeDir, "aabb0011", req)
	if err == nil {
		t.Error("GetTokenFromDaemon with no daemon should fail")
	}
}

// Attack vector: Send to a socket that accepts but never responds.
func TestAdv_ShimHanging(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			go func() {
				time.Sleep(1 * time.Minute)
				conn.Close()
			}()
		}
	}()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err = sendRequestWithTimeout(runtimeDir, req, 500*time.Millisecond)
	if err == nil {
		t.Error("should timeout with hanging server")
	}
}

// Attack vector: Server responds with partial JSON.
func TestAdv_ShimPartialResp(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			conn.Write([]byte(`{"version":2,"status":"ok","up`))
			conn.Close()
		}
	}()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err = sendRequest(runtimeDir, req)
	if err == nil {
		t.Error("partial response should cause decode error")
	}
}

// Attack vector: Server responds with invalid JSON.
func TestAdv_ShimBadJSON(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			conn.Write([]byte("NOT JSON\n"))
			conn.Close()
		}
	}()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err = sendRequest(runtimeDir, req)
	if err == nil {
		t.Error("invalid JSON response should cause error")
	}
}

// Attack vector: Server responds with oversized JSON.
func TestAdv_ShimOversizedResp(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			// Send a valid JSON object with a 2MB error field
			bigErr := make([]byte, 2<<20)
			for i := range bigErr {
				bigErr[i] = 'A'
			}
			conn.Write([]byte(`{"version":2,"status":"error","error":"`))
			conn.Write(bigErr)
			conn.Write([]byte("\"}\n"))
			conn.Close()
		}
	}()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	resp, err := sendRequest(runtimeDir, req)
	if err == nil {
		t.Logf("FINDING: Shim accepted 2MB response (no limit). Error length: %d", len(resp.Error))
	} else {
		t.Logf("oversized response: %v", err)
	}
}

// Attack vector: Concurrent GetTokenFromDaemon calls.
func TestAdv_ShimConcurrent(t *testing.T) {
	runtimeDir, cleanup := shortStartTestDaemon(t)
	defer cleanup()

	testToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"

	req := daemon.Request{
		IssuerURL: "https://example.com",
		ClientID:  "test",
	}
	_, err := StoreToken(runtimeDir, "ccdd2233", req, testToken, "rt")
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			resp, err := GetTokenFromDaemon(runtimeDir, "ccdd2233", req)
			if err != nil || resp.Status != "ok" || resp.Token != testToken {
				if err != nil {
					t.Logf("concurrent get err: %v", err)
				} else {
					t.Logf("concurrent get: status=%s", resp.Status)
				}
			}
		}()
	}
	wg.Wait()
}

// Attack vector: Socket path that is a regular file.
func TestAdv_ShimFileSocket(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
	os.WriteFile(socketPath, []byte("not a socket"), 0600)

	_, err := sendRequest(runtimeDir, daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	})
	if err == nil {
		t.Error("regular file as socket should fail")
	}
}

// Attack vector: sendShutdown to server that doesn't read.
func TestAdv_ShimShutdownNoRead(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			conn.Close()
		}
	}()

	err = sendShutdown(runtimeDir)
	t.Logf("shutdown to non-reading server: err=%v", err)
}

// Attack vector: sendRequest where daemon closes connection before we read.
func TestAdv_ShimDropConn(t *testing.T) {
	runtimeDir, cleanup := shortRuntimeDir(t)
	defer cleanup()

	socketPath := filepath.Join(runtimeDir, "sock")
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
			// Read request then close immediately (no response)
			var req daemon.Request
			json.NewDecoder(conn).Decode(&req)
			conn.Close()
		}
	}()

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	_, err = sendRequest(runtimeDir, req)
	if err == nil {
		t.Error("dropped connection should cause error")
	}
}

// Attack vector: negative timeout in TransportDial should not panic.
func TestAdv_ShimDialNeg(t *testing.T) {
	addr := daemon.TransportAddress(filepath.Join(t.TempDir(), "no-such-dir"))
	_, err := daemon.TransportDial(addr, -1*time.Second)
	if err == nil {
		t.Error("TransportDial with -1s should fail")
	}
}
