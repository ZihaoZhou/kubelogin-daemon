package shim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// getTokenTimeout is the maximum time get-token waits for a daemon response.
// 12s accommodates cold start (fork + waitForSocket ~2.5s) + daemon init
// (token load + OIDC discovery ~2-3s) + version mismatch recovery
// (shutdown ~0.6s + verify ~0.6s + kill + autostart ~2.5s) + retry backoff,
// while still failing fast on genuinely hung daemons. kubectl calls get-token
// 5-7 times during API discovery; each is a separate process with its own deadline.
const getTokenTimeout = 12 * time.Second

// GetTokenFromDaemon connects to the daemon and requests a token.
// If the daemon is not running, it auto-starts one.
// Enforces a 5-second timeout on the entire operation (including auto-start and retries).
func GetTokenFromDaemon(runtimeDir, cacheKey string, req daemon.Request) (*daemon.Response, error) {
	req.Version = daemon.ProtocolVersion
	req.Command = "get-token"
	req.CacheKey = cacheKey

	deadline := time.Now().Add(getTokenTimeout)

	// Try to connect to the daemon, with auto-start and retries.
	// kubectl calls get-token 5-7 times concurrently during API discovery.
	// The first call triggers auto-start; concurrent calls must wait for
	// the daemon to become ready rather than failing immediately.
	var resp *daemon.Response
	var err error
	autoStarted := false

	for attempt := 0; attempt < 3; attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("get-token deadline exceeded")
		}
		resp, err = sendRequestWithTimeout(runtimeDir, req, remaining)
		if err == nil {
			break
		}
		if !isConnectionRefused(err) && !isNoSuchFile(err) {
			return nil, fmt.Errorf("connect to daemon: %w", err)
		}
		// Daemon not running — auto-start once, then retry with backoff
		if !autoStarted {
			if startErr := AutoStartDaemon(runtimeDir); startErr != nil {
				return nil, fmt.Errorf("auto-start daemon failed: %w", startErr)
			}
			autoStarted = true
		} else {
			// Already auto-started, wait a bit for daemon to become ready
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("connect after auto-start: %w", err)
	}

	// Handle version mismatch
	if resp.Status == "error" && resp.DaemonVersion != daemon.ProtocolVersion {
		// Old daemon running — shut it down and start a new one.
		// The old daemon's PID is available from the version-mismatch response.
		oldPID := resp.PID

		shutdownErr := sendShutdown(runtimeDir)

		// Verify the old daemon is actually gone by polling the transport.
		addr := daemon.TransportAddress(runtimeDir)
		daemonGone := false
		for i := 0; i < 6; i++ {
			time.Sleep(100 * time.Millisecond)
			if !daemon.TransportProbeAlive(addr, 500*time.Millisecond) {
				daemonGone = true
				break
			}
		}

		// If shutdown failed or daemon is still alive, kill by PID.
		if !daemonGone {
			if oldPID > 0 && oldPID != os.Getpid() {
				if proc, err := os.FindProcess(oldPID); err == nil {
					_ = proc.Kill()
					time.Sleep(200 * time.Millisecond)
				}
			} else if shutdownErr != nil {
				return nil, fmt.Errorf("version mismatch: shutdown failed and no PID available: %w", shutdownErr)
			}
		}

		rem := time.Until(deadline)
		if rem <= 0 {
			return nil, fmt.Errorf("get-token deadline exceeded after version mismatch restart")
		}
		if err := AutoStartDaemon(runtimeDir); err != nil {
			return nil, fmt.Errorf("restart daemon after version mismatch: %w", err)
		}
		rem = time.Until(deadline)
		if rem <= 0 {
			return nil, fmt.Errorf("get-token deadline exceeded after restart")
		}
		resp, err = sendRequestWithTimeout(runtimeDir, req, rem)
		if err != nil {
			return nil, fmt.Errorf("connect after restart: %w", err)
		}
	}

	return resp, nil
}

// StoreToken sends a freshly obtained token to the daemon for management.
func StoreToken(runtimeDir, cacheKey string, req daemon.Request, idToken, refreshToken string) (*daemon.Response, error) {
	req.Version = daemon.ProtocolVersion
	req.Command = "store-token"
	req.CacheKey = cacheKey
	req.IDToken = idToken
	req.RefreshToken = refreshToken
	return sendRequest(runtimeDir, req)
}

// SendBeginLogin tells the daemon that a login flow is starting.
func SendBeginLogin(runtimeDir, cacheKey string) (*daemon.Response, error) {
	req := daemon.Request{
		Version:  daemon.ProtocolVersion,
		Command:  "begin-login",
		CacheKey: cacheKey,
	}
	return sendRequest(runtimeDir, req)
}

// SendCancelLogin tells the daemon that a login flow was cancelled.
func SendCancelLogin(runtimeDir, cacheKey string) (*daemon.Response, error) {
	req := daemon.Request{
		Version:  daemon.ProtocolVersion,
		Command:  "cancel-login",
		CacheKey: cacheKey,
	}
	return sendRequest(runtimeDir, req)
}

// SendCheck requests the current token status from the daemon.
func SendCheck(runtimeDir, cacheKey string) (*daemon.Response, error) {
	req := daemon.Request{
		Version:  daemon.ProtocolVersion,
		Command:  "check",
		CacheKey: cacheKey,
	}
	return sendRequest(runtimeDir, req)
}

// SendRefresh requests a forced token refresh from the daemon.
func SendRefresh(runtimeDir, cacheKey string, providerReq daemon.Request) (*daemon.Response, error) {
	providerReq.Version = daemon.ProtocolVersion
	providerReq.Command = "refresh"
	providerReq.CacheKey = cacheKey
	return sendRequest(runtimeDir, providerReq)
}

// SendHealth sends a health check to the daemon.
func SendHealth(runtimeDir string) (*daemon.Response, error) {
	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
	}
	return sendRequest(runtimeDir, req)
}

// SendShutdown sends a shutdown command to the daemon.
func SendShutdown(runtimeDir string) error {
	return sendShutdown(runtimeDir)
}

func sendRequest(runtimeDir string, req daemon.Request) (*daemon.Response, error) {
	// SEC-9: Read daemon nonce for mutual authentication.
	req.Nonce = readDaemonNonce(runtimeDir)

	addr := daemon.TransportAddress(runtimeDir)
	conn, err := daemon.TransportDial(addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send request
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// SEC-3: Limit response size to prevent OOM from rogue daemon responses.
	var resp daemon.Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}

// sendRequestWithTimeout sends a request with a strict overall deadline.
// Used by get-token to enforce the 2s SLA.
func sendRequestWithTimeout(runtimeDir string, req daemon.Request, timeout time.Duration) (*daemon.Response, error) {
	// SEC-9: Read daemon nonce for mutual authentication.
	req.Nonce = readDaemonNonce(runtimeDir)

	addr := daemon.TransportAddress(runtimeDir)
	conn, err := daemon.TransportDial(addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// SEC-3: Limit response size to prevent OOM from rogue daemon responses.
	var resp daemon.Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}

func sendShutdown(runtimeDir string) error {
	// SEC-CRIT-2: Read nonce for shutdown too — without it, any same-UID process
	// can kill the daemon. Nonce proves the caller can read the 0700 runtime dir.
	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "shutdown",
		Nonce:   readDaemonNonce(runtimeDir),
	}
	addr := daemon.TransportAddress(runtimeDir)
	conn, err := daemon.TransportDial(addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("write shutdown request: %w", err)
	}

	// Read and verify the daemon's response to confirm shutdown was accepted.
	var resp daemon.Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp); err != nil {
		return fmt.Errorf("read shutdown response: %w", err)
	}
	if resp.Status != "ok" {
		return fmt.Errorf("shutdown rejected: %s", resp.Status)
	}
	return nil
}

// readDaemonNonce reads the nonce file from the daemon's runtime directory.
// Returns empty string if the file doesn't exist (backward compatibility).
func readDaemonNonce(runtimeDir string) string {
	noncePath := filepath.Join(runtimeDir, "nonce")
	// SEC-HIGH-1: Reject symlinks before reading, consistent with every other
	// file operation in the IPC chain (openNoFollow, Lstat checks).
	// A same-UID attacker who symlinks the nonce file could redirect the read
	// to observe the nonce value or cause a DoS via /dev/null.
	info, err := os.Lstat(noncePath)
	if err != nil {
		return "" // nonce file missing — old daemon, skip verification
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "" // symlink — reject
	}
	// SEC-HIGH-3: Limit read to 1KB. A valid nonce is 32 hex chars (16 bytes).
	// Unbounded ReadFile could OOM if the file is replaced with a large one.
	f, err := os.Open(noncePath)
	if err != nil {
		return ""
	}
	defer f.Close()
	data := make([]byte, 1024)
	n, _ := f.Read(data)
	return strings.TrimSpace(string(data[:n]))
}

func isConnectionRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func isNoSuchFile(err error) bool {
	return errors.Is(err, syscall.ENOENT)
}
