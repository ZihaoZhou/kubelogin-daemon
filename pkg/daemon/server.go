package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/jwt"
	"github.com/ZihaoZhou/kubelogin-daemon/pkg/oidc"
)

// maxConcurrentConns is the maximum number of concurrent connections the daemon will handle.
// Beyond this limit, connections are accepted but immediately closed. This prevents goroutine
// exhaustion from local DoS (slow clients holding connections).
const maxConcurrentConns = 256

// maxTokenManagers is the maximum number of TokenManagers the daemon will hold in memory.
// In practice, a machine has 1-5 OIDC providers. This prevents memory exhaustion from
// an attacker spamming store-token with many unique valid hex cache keys.
const maxTokenManagers = 256

// maxConcurrentWakeRefresh limits the number of concurrent OIDC refreshes after
// a sleep/wake event. Prevents thundering herd at the OIDC provider (ROB-3).
const maxConcurrentWakeRefresh = 10

// Server is the daemon server that listens on a Unix socket.
type Server struct {
	runtimeDir    string
	socketPath    string
	listener      net.Listener
	logger        *Logger
	managers      sync.Map // map[string]*TokenManager
	states        *StateManager
	startTime     time.Time
	idleTimeout   time.Duration
	lastRequest   atomic.Int64 // unix timestamp of last request
	uid           uint32
	idleCheckTick time.Duration
	shutdown      chan struct{}
	shutdownOnce  sync.Once
	wg            sync.WaitGroup
	connSem       chan struct{} // semaphore for connection limiting
	// ROB-2: managerMu protects the cap-check + LoadOrStore + count increment
	// sequence to prevent concurrent goroutines from exceeding maxTokenManagers.
	managerMu    sync.Mutex
	managerCount int32 // number of active token managers (for cap enforcement)
	// SEC-9: Nonce for mutual authentication between shim and daemon.
	nonce string
	// MED-1: Server-level semaphore for post-wake refresh concurrency limiting.
	// Prevents 2x concurrent refreshes when rapid sleep/wake cycles each create
	// their own local semaphore.
	wakeSem chan struct{}
	// B2: Socket inode recorded at bind time. Used by idleWatcher to detect
	// socket file deletion or replacement (another daemon bound a new socket).
	socketInode uint64
	// Shutdown context: cancelled on Shutdown() to immediately close all
	// active connections. Replaces the old activeConns + wg.Wait() approach.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

// ServerConfig configures the daemon server.
type ServerConfig struct {
	RuntimeDir    string
	Logger        *Logger
	IdleTimeout   time.Duration // default 0 (never idle-timeout); set >0 to enable
	IdleCheckTick time.Duration // default 30 seconds (exposed for testing)
}

// NewServer creates a new daemon server.
func NewServer(cfg ServerConfig) *Server {
	// IdleTimeout <= 0 means never idle-timeout. The daemon stays alive
	// so proactive refresh keeps tokens valid indefinitely.
	if cfg.IdleTimeout < 0 {
		cfg.IdleTimeout = 0
	}
	if cfg.IdleCheckTick <= 0 {
		cfg.IdleCheckTick = 30 * time.Second
	}
	socketPath := TransportAddress(cfg.RuntimeDir)
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		runtimeDir:     cfg.RuntimeDir,
		socketPath:     socketPath,
		logger:         cfg.Logger,
		states:         NewStateManager(),
		startTime:      time.Now(),
		idleTimeout:    cfg.IdleTimeout,
		uid:            platformUID(), // COMPAT-10: platform-specific UID (avoids os.Getuid()=-1 on Windows)
		idleCheckTick:  cfg.IdleCheckTick,
		shutdown:       make(chan struct{}),
		connSem:        make(chan struct{}, maxConcurrentConns),
		wakeSem:        make(chan struct{}, maxConcurrentWakeRefresh),
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}
	s.lastRequest.Store(time.Now().Unix())
	return s
}

// SocketPath returns the socket path.
func (s *Server) SocketPath() string {
	return s.socketPath
}

// RegisterTokenManager registers a TokenManager for a cache key.
func (s *Server) RegisterTokenManager(cacheKey string, tm *TokenManager) {
	s.managers.Store(cacheKey, tm)
}

// GetOrCreateTokenManager gets an existing token manager or signals that one is needed.
func (s *Server) GetTokenManager(cacheKey string) (*TokenManager, bool) {
	v, ok := s.managers.Load(cacheKey)
	if !ok {
		return nil, false
	}
	return v.(*TokenManager), true
}

// ListenAndServe starts listening on the Unix socket and serving requests.
//
// BIND-FIRST PRINCIPLE (B1): The socket bind MUST be the first blocking
// operation after runtime dir creation. This is the singleton election —
// if another daemon already holds the socket, we must exit immediately.
// Any operations before bind (security checks, temp cleanup, socket probing)
// delay the exit and cause orphan process accumulation under thundering herd.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Reject symlinks at runtime dir path to prevent symlink attacks in /tmp
	if info, err := os.Lstat(s.runtimeDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime dir %s is a symlink (possible attack, refusing to start)", s.runtimeDir)
		}
	}

	// SEC-CRIT-5: Use os.Mkdir (not MkdirAll) to prevent symlink TOCTOU.
	if err := os.Mkdir(s.runtimeDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create runtime dir: %w", err)
	}

	// B1: BIND FIRST — probe and bind the transport before any other operations.
	// ROB-1: Probe existing transport before attempting bind.
	if TransportProbeAlive(s.socketPath, 2*time.Second) {
		return fmt.Errorf("another daemon is already listening on %s", s.socketPath)
	}
	// On Unix, remove stale socket file before bind.
	TransportCleanup(s.socketPath, 0)

	// Bind the transport — this is the singleton election.
	// If this fails with EADDRINUSE (Unix) or access denied (Windows pipe),
	// the caller (runDaemonStart) exits immediately.
	listener, inode, err := TransportListen(s.socketPath)
	if err != nil {
		return fmt.Errorf("bind %s: %w", s.socketPath, err)
	}
	s.listener = listener
	s.socketInode = inode

	// --- We won the election. Now do security hardening and setup. ---

	// Harden permissions on the directory (platform-specific: chmod on Unix, ACL on Windows)
	if err := setPrivatePermissions(s.runtimeDir, true); err != nil {
		listener.Close()
		TransportCleanup(s.socketPath, 0)
		return fmt.Errorf("set runtime dir permissions: %w", err)
	}

	// Verify directory security (platform-specific: Unix perms / Windows ACLs)
	if err := validateRuntimeDirSecurity(s.runtimeDir); err != nil {
		listener.Close()
		TransportCleanup(s.socketPath, 0)
		return fmt.Errorf("runtime dir security check: %w", err)
	}

	// Harden socket file permissions on Unix. On Windows, named pipe security
	// is handled by the SDDL passed to winio.ListenPipe at bind time.
	if s.socketInode != 0 {
		if err := setPrivatePermissions(s.socketPath, false); err != nil {
			listener.Close()
			TransportCleanup(s.socketPath, 0)
			return fmt.Errorf("set socket permissions: %w", err)
		}
	}

	// ROB-7: Clean up stale temp files left by a previous crash.
	cleanupStaleTempFiles(s.runtimeDir, s.logger)

	// SEC-9: Generate and write a nonce file for mutual authentication.
	if err := s.generateNonce(); err != nil {
		listener.Close()
		TransportCleanup(s.socketPath, 0)
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Disable core dumps (tokens in memory)
	disableCoreDump()

	if s.idleTimeout > 0 {
		s.logger.Infof("daemon listening on %s (idle timeout: %s)", s.socketPath, s.idleTimeout)
	} else {
		s.logger.Infof("daemon listening on %s (no idle timeout)", s.socketPath)
	}

	// Start idle timeout watcher
	s.wg.Add(1)
	go s.idleWatcher(ctx)

	// Watch for context cancellation and close listener
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Accept loop
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			default:
				// ROB-8: Log the actual error for diagnostics. Timeout errors are
				// retryable; all other accept errors (e.g., socket deleted) are fatal.
				if !isAcceptRetryable(err) {
					s.logger.Errorf("fatal accept error (exiting): %v", err)
					return fmt.Errorf("fatal accept error: %w", err)
				}
				s.logger.Warnf("transient accept error (retrying): %v", err)
				continue
			}
		}
		// Connection limiting: reject if at capacity
		select {
		case s.connSem <- struct{}{}:
			// Got a slot — handle the connection
			s.wg.Add(1)
			go s.handleConnection(conn)
		default:
			// At capacity — reject immediately
			conn.Close()
		}
	}
}

// Shutdown shuts down the server. Safe to call multiple times.
//
// Two steps:
//  1. Stop everything: signal shutdown, cancel all active connections,
//     remove socket, close listener, stop refresh timers, clean up nonce.
//  2. Return. Process exits when main() returns. Leaked goroutines are
//     killed by process exit.
//
// No waiting for goroutines (wg.Wait). No persist-on-shutdown (B3 persists
// on every successful refresh). No deadline. Shutdown completes in <100ms.
func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		s.logger.Infof("shutting down daemon")

		// Step 1: Stop everything.
		close(s.shutdown)    // signal goroutines (idleWatcher, wake-refresh)
		s.shutdownCancel()   // cancel all active connections immediately

		// B2: Remove transport artifacts BEFORE closing listener.
		// listener.Close() causes the accept loop to return. Callers check
		// for removal immediately after ListenAndServe returns.
		// On Unix: removes socket file with inode check.
		// On Windows: no-op (named pipes are kernel-managed).
		TransportCleanup(s.socketPath, s.socketInode)
		if s.listener != nil {
			s.listener.Close()
		}

		// Stop proactive refresh timers (prevents new refresh goroutines).
		s.managers.Range(func(key, value any) bool {
			value.(*TokenManager).Stop()
			return true
		})

		// Clean up nonce file.
		os.Remove(filepath.Join(s.runtimeDir, "nonce"))

		s.logger.Infof("daemon stopped")

		// Step 2: Return. Process exits when main() returns.
	})
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() { <-s.connSem }() // release connection slot
	defer s.wg.Done()
	defer conn.Close()

	// Cancel this connection when shutdown fires. The goroutine exits when
	// either shutdown cancels the context OR the connection handler returns
	// normally (connDone closes). Without connDone, this goroutine would
	// leak until daemon shutdown for every completed connection.
	connDone := make(chan struct{})
	defer close(connDone)
	go func() {
		select {
		case <-s.shutdownCtx.Done():
			conn.Close() // safe: double-close on net.Conn is a no-op
		case <-connDone:
			// Connection completed normally, goroutine exits.
		}
	}()

	// SEC-CRIT-1: Recover from panics in connection handling.
	// singleflight.Do propagates panics to ALL waiting callers, so a single
	// malformed token causing a panic in Refresh() would cascade to every
	// concurrent get-token request. recover() isolates the blast radius.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Errorf("panic in handleConnection (recovered): %v", r)
		}
	}()

	// Set read deadline to prevent stuck connections during normal operation.
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Verify peer UID (defense in depth beyond directory permissions)
	if err := verifyPeerUID(conn, s.uid); err != nil {
		s.logger.Warnf("rejected connection: %v", err)
		return
	}

	// Decode request (limited to 1MB to prevent oversized payloads).
	// COMPAT-6: Do NOT use DisallowUnknownFields — it breaks forward compatibility.
	// A newer shim may send fields the current daemon doesn't recognize; silently
	// ignoring them allows graceful version skew. Protocol version check (below)
	// handles incompatible changes.
	var req Request
	decoder := json.NewDecoder(io.LimitReader(conn, 1<<20))
	if err := decoder.Decode(&req); err != nil {
		s.writeResponse(conn, errorResponse(fmt.Sprintf("invalid request: %v", err)))
		return
	}
	// Reject trailing non-whitespace data after the JSON object.
	// The decoder buffers ahead; check its internal buffer for leftover content.
	if buffered := decoder.Buffered(); buffered != nil {
		rest, _ := io.ReadAll(buffered)
		if len(strings.TrimSpace(string(rest))) > 0 {
			s.writeResponse(conn, errorResponse("trailing data after JSON request"))
			return
		}
	}

	// SEC-CRIT-1: Verify nonce for mutual authentication.
	// Nonce is required — proves the client can read the 0700 runtime directory.
	// A process that connects to the socket without reading the nonce file is rejected.
	// SEC-HIGH-2: Use constant-time comparison to prevent timing side-channel
	// attacks on the nonce (e.g., from container namespace misconfigurations
	// where socket access doesn't imply file access).
	if subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(s.nonce)) != 1 {
		s.logger.Warnf("rejected request with invalid nonce (possible socket hijack)")
		s.writeResponse(conn, errorResponse("invalid nonce: daemon identity verification failed"))
		return
	}

	// ROB-LOW-2: Update last request time AFTER nonce verification.
	// Previously this was before nonce check, so invalid-nonce connections
	// would reset the idle timer, preventing the daemon from shutting down.
	s.lastRequest.Store(time.Now().Unix())

	// Version check — include PID so the shim's version-mismatch handler
	// can kill the old daemon by PID if graceful shutdown fails.
	if req.Version != ProtocolVersion {
		s.writeResponse(conn, Response{
			Version:       ProtocolVersion,
			DaemonVersion: ProtocolVersion,
			Status:        "error",
			Error:         fmt.Sprintf("unsupported protocol version %d", req.Version),
			PID:           os.Getpid(),
		})
		return
	}

	// Dispatch command
	switch req.Command {
	case "get-token":
		s.handleGetToken(conn, req)
	case "store-token":
		s.handleStoreToken(conn, req)
	case "begin-login":
		s.handleBeginLogin(conn, req)
	case "cancel-login":
		s.handleCancelLogin(conn, req)
	case "check":
		s.handleCheck(conn, req)
	case "refresh":
		s.handleRefresh(conn, req)
	case "health":
		s.handleHealth(conn)
	case "shutdown":
		s.writeResponse(conn, Response{
			Version:       ProtocolVersion,
			DaemonVersion: ProtocolVersion,
			Status:        "ok",
		})
		go s.Shutdown()
	default:
		s.writeResponse(conn, errorResponse(fmt.Sprintf("unknown command: %s", req.Command)))
	}
}

func (s *Server) handleGetToken(conn net.Conn, req Request) {
	cacheKey := req.CacheKey
	if cacheKey == "" {
		s.writeResponse(conn, errorResponse("cache_key is required"))
		return
	}
	if !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}

	// Check state machine first — if login is in progress, return immediately
	state, loginStarted := s.states.GetState(cacheKey)
	if state == StateLoginInProgress {
		resp := errorCodeResponse(
			ErrCodeLoginInProgress,
			"Login is in progress",
			"Retry in 5 seconds (login started "+time.Since(loginStarted).Round(time.Second).String()+" ago)",
		)
		resp.Status = "login-in-progress"
		resp.LoginStartedAt = &loginStarted
		s.writeResponse(conn, resp)
		return
	}

	tm := s.getOrCreateTokenManager(cacheKey, req)
	if tm == nil {
		// No persisted token and no existing manager — need initial auth
		s.states.SetState(cacheKey, StateNeedsLogin)
		s.writeResponse(conn, needsAuthResponse())
		return
	}

	// Check if we have a valid (non-expired) token
	// COMPAT-CRIT-3: If force_refresh is set, skip the cache and go straight to refresh.
	idToken, expiry, hasToken := tm.GetToken()
	if hasToken && !time.Now().After(expiry) && !req.ForceRefresh {
		s.states.SetState(cacheKey, StateValid)
		s.writeResponse(conn, tokenResponse(idToken, expiry))
		return
	}

	// Token expired or missing — try to refresh
	s.states.SetState(cacheKey, StateRefreshing)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	idToken, expiry, err := tm.Refresh(ctx)
	if err != nil {
		s.logger.Warnf("on-demand refresh failed for %s: %v", cacheKey, err)
		s.states.SetState(cacheKey, StateNeedsLogin)
		// Classify the error for structured response
		s.writeResponse(conn, classifyRefreshError(err))
		return
	}
	s.states.SetState(cacheKey, StateValid)
	s.writeResponse(conn, tokenResponse(idToken, expiry))
}

// getOrCreateTokenManager returns an existing token manager or creates one
// by loading persisted tokens. Returns nil if no token is available.
func (s *Server) getOrCreateTokenManager(cacheKey string, req Request) *TokenManager {
	// Fast path: already have a manager
	if v, ok := s.managers.Load(cacheKey); ok {
		existing := v.(*TokenManager)
		// ROB-2: Update refresher config on every request so rotated credentials
		// and changed TLS settings take effect without daemon restart.
		existing.SetRefresher(&OIDCRefresher{
			Provider:    providerFromRequest(req),
			TLSConfig:   req.TLSConfig,
			ExtraParams: req.ExtraParams,
			Logger:      s.logger,
		})
		return existing
	}

	// Slow path: try to load persisted token and create manager
	idToken, refreshToken, err := LoadPersistedToken(s.runtimeDir, cacheKey)
	if err != nil {
		s.logger.Warnf("load persisted token for %s: %v", cacheKey, err)
		return nil
	}
	if refreshToken == "" {
		// No persisted token — needs initial auth
		return nil
	}

	// Build the refresher from the request's provider config
	// COMPAT-CRIT-2: Include TLS config so refreshes work with custom CAs/skip-verify.
	refresher := &OIDCRefresher{
		Provider:    providerFromRequest(req),
		TLSConfig:   req.TLSConfig,
		ExtraParams: req.ExtraParams,
		Logger:      s.logger,
	}

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: s.runtimeDir,
		CacheKey:   cacheKey,
		Logger:     s.logger,
	})

	// Parse expiry from the persisted ID token
	var expiry time.Time
	if idToken != "" {
		claims, err := parseTokenExpiry(idToken)
		if err != nil {
			s.logger.Warnf("parse persisted token expiry: %v", err)
			// Token might be expired — still set it, refresh will fix it
			expiry = time.Now()
		} else {
			expiry = claims
		}
	} else {
		expiry = time.Now() // force immediate refresh
	}

	tm.SetInitialToken(idToken, refreshToken, expiry)

	// ROB-2: Use mutex to make cap-check + LoadOrStore + count-increment atomic.
	// Without this, two concurrent goroutines can both pass the cap check and
	// both store, exceeding maxTokenManagers.
	s.managerMu.Lock()

	// ROB-3: If cap reached, evict the least-recently-used manager before rejecting.
	if s.managerCount >= int32(maxTokenManagers) {
		if !s.evictOldestManagerLocked() {
			s.managerMu.Unlock()
			tm.Stop()
			s.logger.Warnf("token manager cap reached (%d) and no evictable managers for %s", maxTokenManagers, cacheKey)
			return nil
		}
	}

	// Store atomically — if another connection raced us, use theirs
	actual, loaded := s.managers.LoadOrStore(cacheKey, tm)
	if loaded {
		s.managerMu.Unlock()
		// Another goroutine won the race — stop our manager and use theirs
		tm.Stop()
		existing := actual.(*TokenManager)
		// ROB-2: Update the existing manager's refresher with the new request's
		// config. Without this, rotated client secrets, changed CA certs, or
		// modified extra params from kubeconfig are silently ignored until
		// daemon restart — causing refresh failures.
		existing.SetRefresher(&OIDCRefresher{
			Provider:    providerFromRequest(req),
			TLSConfig:   req.TLSConfig,
			ExtraParams: req.ExtraParams,
			Logger:      s.logger,
		})
		return existing
	}
	s.managerCount++
	s.managerMu.Unlock()
	s.logger.Infof("created token manager for provider %s (from persisted token)", req.IssuerURL)
	return tm
}

func (s *Server) handleHealth(conn net.Conn) {
	uptimeDur := time.Since(s.startTime).Round(time.Second)
	resp := Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		Uptime:        uptimeDur.String(),
		PID:           os.Getpid(),
		LogPath:       s.logger.FilePath(),
		RuntimeDir:    s.runtimeDir,
		UptimeSeconds: int(uptimeDur.Seconds()),
	}
	resp.BinaryPath, _ = os.Executable()

	// Count token managers and include expiry of first
	tokenCount := 0
	s.managers.Range(func(key, value any) bool {
		tokenCount++
		if tokenCount == 1 {
			tm := value.(*TokenManager)
			_, expiry, ok := tm.GetToken()
			if ok {
				resp.TokenExpiry = &expiry
			}
		}
		return true
	})
	resp.TokenCount = tokenCount

	s.writeResponse(conn, resp)
}

func (s *Server) writeResponse(conn net.Conn, resp Response) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		s.logger.Warnf("write response error: %v", err)
	}
}

func (s *Server) idleWatcher(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.idleCheckTick)
	defer ticker.Stop()
	lastTick := time.Now()
	var tickCount uint64

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			drift := now.Sub(lastTick)
			lastTick = now
			tickCount++

			// B2: Socket/pipe liveness detection for ghost daemon prevention.
			// Unix (socketInode != 0): stat the socket file, check inode match.
			// Windows (socketInode == 0): no-op — named pipes are kernel-managed
			// and only one process can listen on a given pipe name at a time,
			// so ghost daemons are impossible.
			if s.socketInode != 0 {
				if info, err := os.Stat(s.socketPath); err != nil {
					s.logger.Warnf("socket file %s disappeared, shutting down (ghost daemon prevention)", s.socketPath)
					s.Shutdown()
					return
				} else if fileInode(info) != s.socketInode {
					s.logger.Warnf("socket file %s replaced (inode changed), shutting down (ghost daemon prevention)", s.socketPath)
					s.Shutdown()
					return
				}
			}

			// Sleep/wake detection: if the drift is > 2x tick interval,
			// we likely slept. Trigger proactive refresh for expired tokens.
			if drift > 2*s.idleCheckTick {
				s.logger.Infof("sleep/wake detected (drift %s > %s), checking token freshness",
					drift.Round(time.Second), (2 * s.idleCheckTick).String())
				s.refreshExpiredTokensAfterWake(ctx)
			}

			// Periodic eviction of stale state entries to bound memory
			s.states.EvictStale()

			// ROB-7: Periodic temp file cleanup (every ~60 ticks ≈ 30min at 30s tick).
			// Covers temp files orphaned by mid-operation crashes during runtime,
			// not just those left from a previous daemon startup.
			if tickCount%60 == 0 {
				cleanupStaleTempFiles(s.runtimeDir, s.logger)
			}

			// Idle timeout: only active when configured (> 0).
			// Default is 0 (never timeout) -- daemon stays alive so proactive
			// refresh keeps tokens valid and users never need to re-login.
			if s.idleTimeout > 0 {
				lastReq := time.Unix(s.lastRequest.Load(), 0)
				idle := time.Since(lastReq)
				if idle > s.idleTimeout {
					s.logger.Infof("idle timeout reached (%s > %s), shutting down", idle.Round(time.Second), s.idleTimeout)
					s.Shutdown()
					return
				}
			}
		case <-s.shutdown:
			return
		case <-ctx.Done():
			return
		}
	}
}

// refreshExpiredTokensAfterWake triggers immediate refresh for all token managers
// with expired or soon-to-expire tokens. Called after detecting a sleep/wake event.
//
// ROB-CRIT-2: This is non-blocking — it spawns goroutines and returns immediately.
// The previous implementation used wakeWg.Wait() which blocked the idle watcher
// goroutine. If N managers all need refresh (30s timeout each) and the semaphore
// limits concurrency to 10, the idle watcher could block for N/10 * 30s, during
// which idle timeout checks, state eviction, and further sleep/wake detection
// are all stalled.
func (s *Server) refreshExpiredTokensAfterWake(ctx context.Context) {
	// ROB-3: Limit concurrent OIDC refreshes to prevent thundering herd at the
	// provider after sleep/wake. With 256 managers, all refreshing simultaneously
	// could trigger rate limiting or overwhelm the OIDC provider.
	// MED-1: Use server-level semaphore (s.wakeSem) instead of a per-call local.
	// Rapid sleep/wake cycles would each create independent semaphores, allowing
	// 2x concurrent refreshes. The server-level semaphore bounds the total.
	s.managers.Range(func(key, value any) bool {
		cacheKey := key.(string)
		tm := value.(*TokenManager)
		_, expiry, hasToken := tm.GetToken()
		if !hasToken {
			return true
		}
		// Refresh if expired or expiring within 10 minutes
		if time.Until(expiry) < 10*time.Minute {
			// ROB-3: Track goroutine in s.wg so Shutdown waits for it.
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				// ROB-1: Recover panics in wake-refresh goroutines, consistent
				// with timer callbacks (token_manager.go:231). Without this,
				// a panic during post-wake refresh crashes the entire daemon.
				defer func() {
					if r := recover(); r != nil {
						s.logger.Errorf("panic in post-wake refresh (recovered): %v", r)
					}
				}()
				// ROB-1: Use select to check shutdown channel. Without this,
				// goroutines block indefinitely on semaphore during shutdown
				// if all slots are held by in-flight refreshes.
				select {
				case s.wakeSem <- struct{}{}: // acquire semaphore slot
				case <-s.shutdown:
					return // daemon shutting down, skip refresh
				}
				defer func() { <-s.wakeSem }() // release
				s.logger.Infof("post-wake refresh for %s (expires %s)", cacheKey, expiry.Format(time.RFC3339))
				s.states.SetState(cacheKey, StateRefreshing)
				refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_, _, err := tm.Refresh(refreshCtx)
				cancel()
				if err != nil {
					s.logger.Warnf("post-wake refresh failed for %s: %v", cacheKey, err)
					s.states.SetState(cacheKey, StateNeedsLogin)
				} else {
					s.states.SetState(cacheKey, StateValid)
				}
			}()
		}
		return true
	})
}

func (s *Server) handleStoreToken(conn net.Conn, req Request) {
	cacheKey := req.CacheKey
	if cacheKey == "" {
		s.writeResponse(conn, errorResponse("cache_key is required"))
		return
	}
	if !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}
	if req.IDToken == "" {
		s.writeResponse(conn, errorResponse("id_token is required"))
		return
	}
	// ROB-MED-5: Reject oversized tokens to prevent memory exhaustion.
	// A typical JWT is ~2KB; 1MB is generous while preventing abuse.
	const maxTokenSize = 1 << 20 // 1MB
	if len(req.IDToken) > maxTokenSize || len(req.RefreshToken) > maxTokenSize {
		s.writeResponse(conn, errorResponse("token too large"))
		return
	}

	// Parse expiry from the ID token
	expiry, err := parseTokenExpiry(req.IDToken)
	if err != nil {
		s.writeResponse(conn, errorResponse(fmt.Sprintf("parse token expiry: %v", err)))
		return
	}

	// Build the refresher from the request's provider config
	// COMPAT-CRIT-2: Include TLS config so refreshes work with custom CAs/skip-verify.
	refresher := &OIDCRefresher{
		Provider:    providerFromRequest(req),
		TLSConfig:   req.TLSConfig,
		ExtraParams: req.ExtraParams,
		Logger:      s.logger,
	}

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  refresher,
		PersistDir: s.runtimeDir,
		CacheKey:   cacheKey,
		Logger:     s.logger,
	})

	tm.SetInitialToken(req.IDToken, req.RefreshToken, expiry)

	// ROB-2: Use mutex for atomic cap-check + store + count-increment.
	// ADD-1: Cap check BEFORE persist to avoid leaking token files when cap is exceeded.
	s.managerMu.Lock()
	_, exists := s.managers.Load(cacheKey)
	if !exists && s.managerCount >= int32(maxTokenManagers) {
		// ROB-3: Try eviction before rejecting
		if !s.evictOldestManagerLocked() {
			s.managerMu.Unlock()
			tm.Stop()
			s.logger.Warnf("token manager cap reached (%d), rejecting store-token for new key", maxTokenManagers)
			s.writeResponse(conn, errorResponse("too many token managers"))
			return
		}
	}

	// Store atomically — if another connection raced us, stop ours and use theirs
	actual, loaded := s.managers.LoadOrStore(cacheKey, tm)
	if loaded {
		s.managerMu.Unlock()
		tm.Stop()
		// Update the existing manager with the new token
		existing := actual.(*TokenManager)
		existing.SetInitialToken(req.IDToken, req.RefreshToken, expiry)
		// ROB-3: Update refresher config with the new request's provider settings.
		// login may have changed TLS config, client secret, or extra params.
		existing.SetRefresher(&OIDCRefresher{
			Provider:    providerFromRequest(req),
			TLSConfig:   req.TLSConfig,
			ExtraParams: req.ExtraParams,
			Logger:      s.logger,
		})
		s.logger.Infof("updated existing token manager for %s", req.IssuerURL)
	} else {
		s.managerCount++
		s.managerMu.Unlock()
		s.logger.Infof("created token manager for %s (from store-token)", req.IssuerURL)
	}

	// ADD-1: Persist AFTER cap check (only if manager was accepted)
	if err := PersistToken(s.runtimeDir, cacheKey, req.IDToken, req.RefreshToken); err != nil {
		s.logger.Warnf("persist after store-token: %v", err)
	}

	// Transition state to VALID (completes any LOGIN_IN_PROGRESS)
	s.states.CompleteLogin(cacheKey)

	s.writeResponse(conn, tokenResponse(req.IDToken, expiry))
}

func (s *Server) handleBeginLogin(conn net.Conn, req Request) {
	cacheKey := req.CacheKey
	if cacheKey == "" {
		s.writeResponse(conn, errorResponse("cache_key is required"))
		return
	}
	if !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}

	ok, loginStarted := s.states.BeginLogin(cacheKey)
	if !ok {
		// Already in LOGIN_IN_PROGRESS
		s.writeResponse(conn, Response{
			Version:        ProtocolVersion,
			DaemonVersion:  ProtocolVersion,
			Status:         "login-in-progress",
			ErrorCode:      ErrCodeLoginInProgress,
			Message:        fmt.Sprintf("Login already in progress (started %s ago)", time.Since(loginStarted).Round(time.Second)),
			LoginStartedAt: &loginStarted,
		})
		return
	}
	s.writeResponse(conn, Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		Message:       "Login started",
	})
}

func (s *Server) handleCancelLogin(conn net.Conn, req Request) {
	cacheKey := req.CacheKey
	if cacheKey == "" {
		s.writeResponse(conn, errorResponse("cache_key is required"))
		return
	}
	if !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}

	s.states.CancelLogin(cacheKey)
	s.writeResponse(conn, Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		Message:       "Login cancelled",
	})
}

func (s *Server) handleCheck(conn net.Conn, req Request) {
	cacheKey := req.CacheKey

	// Validate cache_key format if provided (empty is allowed for daemon-only status)
	if cacheKey != "" && !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}

	daemonRunning := true
	resp := Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		DaemonRunning: &daemonRunning,
	}

	if cacheKey == "" {
		// No cache key: report daemon status only
		ready := false
		resp.Ready = &ready
		resp.State = string(StateNeedsLogin)
		resp.Message = "No cache key specified"
		resp.Action = "Run 'kubelogin-daemon login' in a terminal"
		s.writeResponse(conn, resp)
		return
	}

	// If no TokenManager is loaded for this cacheKey, check if a persisted
	// token exists on disk. The daemon doesn't pre-load persisted tokens on
	// startup — they're normally loaded on-demand by get-token. But check
	// needs to know about them too, otherwise a fresh daemon always reports
	// NEEDS_LOGIN even when a valid persist file exists.
	if _, ok := s.managers.Load(cacheKey); !ok {
		if idToken, refreshToken, err := LoadPersistedToken(s.runtimeDir, cacheKey); err == nil && (idToken != "" || refreshToken != "") {
			var expiry time.Time
			if idToken != "" {
				if claims, err := parseTokenExpiry(idToken); err == nil {
					expiry = claims
				}
			}
			hasValidToken := idToken != "" && !time.Now().After(expiry)
			hasRefreshToken := refreshToken != ""

			if hasValidToken {
				ready := true
				resp.Ready = &ready
				resp.State = string(StateValid)
				resp.AccessTokenExpiry = &expiry
				resp.RefreshTokenValid = &hasRefreshToken
				s.writeResponse(conn, resp)
				return
			} else if hasRefreshToken {
				// Token expired but refresh token exists — not NEEDS_LOGIN.
				// Next kubectl call will auto-refresh.
				ready := false
				resp.Ready = &ready
				resp.State = "NEEDS_REFRESH"
				resp.Message = "Token expired but refresh token available. Next kubectl call will auto-refresh."
				resp.RefreshTokenValid = &hasRefreshToken
				s.writeResponse(conn, resp)
				return
			}
		}
	}

	state, loginStarted := s.states.GetState(cacheKey)
	resp.State = string(state)
	if !loginStarted.IsZero() {
		resp.LoginStartedAt = &loginStarted
	}

	switch state {
	case StateValid:
		tm, ok := s.managers.Load(cacheKey)
		if ok {
			tokenMgr := tm.(*TokenManager)
			_, expiry, hasToken := tokenMgr.GetToken()
			if hasToken && !time.Now().After(expiry) {
				ready := true
				rtValid := tokenMgr.CurrentRefreshToken() != ""
				resp.Ready = &ready
				resp.AccessTokenExpiry = &expiry
				resp.RefreshTokenValid = &rtValid
				s.writeResponse(conn, resp)
				return
			}
		}
		// Token manager says VALID but token actually expired — fix state
		s.states.SetState(cacheKey, StateNeedsLogin)
		state = StateNeedsLogin
		resp.State = string(state)
		fallthrough

	case StateNeedsLogin:
		ready := false
		resp.Ready = &ready
		resp.Status = "error"
		resp.ErrorCode = ErrCodeNeedsLogin
		resp.Message = "No valid token. Authentication required."
		resp.Action = "Run 'kubelogin-daemon login' in a terminal"

	case StateLoginInProgress:
		ready := false
		resp.Ready = &ready
		resp.Status = "error"
		resp.ErrorCode = ErrCodeLoginInProgress
		resp.Message = fmt.Sprintf("Login in progress (started %s ago)", time.Since(loginStarted).Round(time.Second))

	case StateRefreshing:
		ready := false
		resp.Ready = &ready
		resp.Message = "Token refresh in progress"
	}

	s.writeResponse(conn, resp)
}

func (s *Server) handleRefresh(conn net.Conn, req Request) {
	cacheKey := req.CacheKey
	if cacheKey == "" {
		s.writeResponse(conn, errorResponse("cache_key is required"))
		return
	}
	if !validCacheKey.MatchString(cacheKey) {
		s.writeResponse(conn, errorResponse("invalid cache_key: must be hex string"))
		return
	}

	tm, ok := s.managers.Load(cacheKey)
	if !ok {
		// Try to load from disk
		tmMgr := s.getOrCreateTokenManager(cacheKey, req)
		if tmMgr == nil {
			s.writeResponse(conn, errorCodeResponse(
				ErrCodeNeedsLogin,
				"No token to refresh. Authentication required.",
				"Run 'kubelogin-daemon login' in a terminal",
			))
			return
		}
		tm = tmMgr
	}

	tokenMgr := tm.(*TokenManager)

	// Check if token is already valid and not near expiry
	_, expiry, hasToken := tokenMgr.GetToken()
	if hasToken && time.Until(expiry) > 30*time.Minute {
		refreshed := false
		s.writeResponse(conn, Response{
			Version:       ProtocolVersion,
			DaemonVersion: ProtocolVersion,
			Status:        "ok",
			Refreshed:     &refreshed,
			Message:       fmt.Sprintf("Token already valid (expires %s)", expiry.Format(time.RFC3339)),
			Expiry:        expiry,
		})
		return
	}

	// Perform refresh
	s.states.SetState(cacheKey, StateRefreshing)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	idToken, newExpiry, err := tokenMgr.Refresh(ctx)
	if err != nil {
		s.logger.Warnf("forced refresh failed for %s: %v", cacheKey, err)
		s.states.SetState(cacheKey, StateNeedsLogin)
		s.writeResponse(conn, classifyRefreshError(err))
		return
	}

	s.states.SetState(cacheKey, StateValid)
	refreshed := true
	s.writeResponse(conn, Response{
		Version:       ProtocolVersion,
		DaemonVersion: ProtocolVersion,
		Status:        "ok",
		Refreshed:     &refreshed,
		Token:         idToken,
		Expiry:        newExpiry,
		Message:       fmt.Sprintf("Token refreshed, expires %s", newExpiry.Format(time.RFC3339)),
	})
}

// classifyRefreshError maps OIDC refresh errors to structured error codes.
func classifyRefreshError(err error) Response {
	errStr := err.Error()
	// Check for permanent failures (token revoked / invalid_grant)
	if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "token has been revoked") {
		return errorCodeResponse(
			ErrCodeTokenRevoked,
			"Refresh token revoked by server",
			"Run 'kubelogin-daemon login' in a terminal",
		)
	}
	// Check for network/discovery errors.
	// SEC-MED-2: Return generic messages instead of raw error strings.
	// OIDC provider errors may contain internal URLs, client IDs, or token hints.
	if strings.Contains(errStr, "oidc discovery") || strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") || strings.Contains(errStr, "i/o timeout") {
		return errorCodeResponse(
			ErrCodeProviderUnreachable,
			"OIDC provider unreachable",
			"Check network connectivity and retry",
		)
	}
	// Check for transient refresh failures
	if strings.Contains(errStr, "refresh") {
		return errorCodeResponse(
			ErrCodeRefreshFailed,
			"Token refresh failed",
			"Retry in 10 seconds, or run 'kubelogin-daemon login' if persistent",
		)
	}
	// Default: needs login
	return needsAuthResponse()
}

// providerFromRequest builds an oidc.Provider from a daemon Request.
func providerFromRequest(req Request) oidc.Provider {
	return oidc.Provider{
		IssuerURL:      req.IssuerURL,
		ClientID:       req.ClientID,
		ClientSecret:   req.ClientSecret,
		ExtraScopes:    req.ExtraScopes,
		UseAccessToken: req.UseAccessToken,
		RequestHeaders: req.RequestHeaders,
		RedirectURL:    req.RedirectURL, // COMPAT-CRIT-1: forward for Keycloak refresh
	}
}

// parseTokenExpiry extracts the expiry time from a JWT token.
// ROB-8: If the JWT has no exp claim (claims.Expiry is zero), return an error
// instead of a zero time. A zero expiry would be treated as "already expired"
// everywhere, triggering immediate refresh loops.
func parseTokenExpiry(token string) (time.Time, error) {
	claims, err := jwt.DecodeWithoutVerify(token)
	if err != nil {
		return time.Time{}, err
	}
	if claims.Expiry.IsZero() {
		return time.Time{}, fmt.Errorf("token has no exp claim")
	}
	return claims.Expiry, nil
}

// isAcceptRetryable returns true for transient accept errors (timeouts) where
// retrying is appropriate. Non-timeout errors (e.g., socket file deleted,
// listener closed) are fatal and should terminate the accept loop.
// ROB-8: Renamed from isTemporaryError to avoid confusion with deprecated
// net.Error.Temporary(). Only Timeout() is checked — this is intentional.
func isAcceptRetryable(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// generateNonce creates a cryptographically random nonce and writes it to the
// runtime directory. The shim reads this file to prove mutual authentication.
// SEC-8: Uses atomic write (temp + fsync + rename) to prevent partial reads
// by a racing shim.
func (s *Server) generateNonce() error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate random nonce: %w", err)
	}
	s.nonce = hex.EncodeToString(b)
	noncePath := filepath.Join(s.runtimeDir, "nonce")

	f, err := os.CreateTemp(s.runtimeDir, "nonce.tmp.*")
	if err != nil {
		return fmt.Errorf("create nonce temp file: %w", err)
	}
	tmpPath := f.Name()
	// SEC-HIGH-3: Restrict temp file permissions before writing the nonce.
	// CreateTemp uses umask-based perms; on permissive umask the nonce could
	// be readable before Rename. Consistent with PersistToken's f.Chmod(0600).
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod nonce temp file: %w", err)
	}
	if _, err := f.Write([]byte(s.nonce)); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write nonce temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("fsync nonce temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close nonce temp file: %w", err)
	}
	if err := os.Rename(tmpPath, noncePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename nonce file: %w", err)
	}
	// SEC-1: Set private permissions on the nonce file (chmod 0600 on Unix, ACL on Windows).
	// The temp file inherits the umask, which may be too permissive.
	if err := setPrivatePermissions(noncePath, false); err != nil {
		return fmt.Errorf("set nonce file permissions: %w", err)
	}
	return nil
}

// evictOldestManagerLocked removes the token manager with the oldest last-access
// time from the sync.Map. Must be called with s.managerMu held.
// ROB-3: Prevents permanent slot exhaustion — managers are now evictable instead
// of accumulating forever until daemon restart.
// ROB-6: Also cleans up the corresponding state entry and persist file to prevent
// orphaned state entries and disk files from accumulating across evictions.
func (s *Server) evictOldestManagerLocked() bool {
	var oldestKey string
	var oldestAccess time.Time
	var oldestTM *TokenManager

	s.managers.Range(func(key, value any) bool {
		tm := value.(*TokenManager)
		access := tm.LastAccess()
		if oldestTM == nil || access.Before(oldestAccess) {
			oldestKey = key.(string)
			oldestAccess = access
			oldestTM = tm
		}
		return true
	})

	if oldestTM == nil {
		return false
	}

	// ROB-HIGH-1: Persist the current token state before eviction so it can be
	// reloaded on next access. This is memory-only eviction — the persist file
	// is deliberately kept on disk. Without this, eviction forces re-authentication
	// even when a valid refresh token exists.
	if idToken, _, ok := oldestTM.GetToken(); ok {
		refreshToken := oldestTM.CurrentRefreshToken()
		if err := PersistToken(s.runtimeDir, oldestKey, idToken, refreshToken); err != nil {
			s.logger.Warnf("persist before eviction for %s: %v", oldestKey, err)
		}
	}

	oldestTM.Stop()
	s.managers.Delete(oldestKey)
	s.managerCount--

	// ROB-6: Clean up state entry to prevent orphaned state from accumulating.
	s.states.DeleteEntry(oldestKey)

	// NOTE: Persist file is deliberately NOT removed. On next access for this
	// cache key, getOrCreateTokenManager will reload the token from disk,
	// avoiding unnecessary re-authentication.

	s.logger.Infof("evicted oldest token manager %s (last access: %s)", oldestKey, oldestAccess.Format(time.RFC3339))
	return true
}

// cleanupStaleTempFiles removes orphan temp files from the runtime directory.
// These are created by atomic write operations (nonce, persist) using CreateTemp.
// If the daemon crashes between CreateTemp and Rename, they accumulate.
//
// SEC-LOW-2: Only removes temp files older than 60 seconds to avoid racing
// with an in-flight PersistToken that just created the temp file but hasn't
// renamed it yet. A fresh temp file (< 60s) is likely still being written.
func cleanupStaleTempFiles(dir string, logger *Logger) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory might not exist yet
	}
	cutoff := time.Now().Add(-60 * time.Second)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Match temp file patterns: "nonce.tmp.*", "<key>.tmp.*", any ".tmp." in name
		if strings.Contains(name, ".tmp.") || strings.HasSuffix(name, ".tmp") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(cutoff) {
				continue // too recent, might be in-flight
			}
			path := filepath.Join(dir, name)
			if err := os.Remove(path); err == nil {
				logger.Infof("cleaned up stale temp file: %s", name)
			}
		}
	}
}
