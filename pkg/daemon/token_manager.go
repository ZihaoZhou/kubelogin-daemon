package daemon

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// Refresher abstracts the OIDC token refresh operation.
type Refresher interface {
	// Refresh exchanges a refresh token for a new token set.
	// Returns idToken, refreshToken, expiry, error.
	Refresh(ctx context.Context, refreshToken string) (idToken, newRefreshToken string, expiry time.Time, err error)
}

// permanentRefreshError indicates a non-retryable refresh failure.
// B3: When the refresh token is empty or revoked, retrying is pointless —
// only re-authentication can recover.
type permanentRefreshError struct {
	reason string
}

func (e *permanentRefreshError) Error() string {
	return e.reason
}

// IsPermanentRefreshError reports whether err is a non-retryable refresh error.
func IsPermanentRefreshError(err error) bool {
	var pe *permanentRefreshError
	return errors.As(err, &pe)
}

// tokenEntry holds a token set and metadata.
type tokenEntry struct {
	idToken      string
	refreshToken string
	expiry       time.Time
	obtainedAt   time.Time
}

// TokenManager manages tokens in memory with proactive refresh.
// All reads are lock-free via atomic.Pointer.
// All refreshes are coalesced via singleflight.
type TokenManager struct {
	current    atomic.Pointer[tokenEntry]
	group      singleflight.Group
	refresherMu sync.Mutex // ROB-2: protects refresher from concurrent read (singleflight) and write (SetRefresher)
	refresher   Refresher
	persistDir  string
	cacheKey    string
	logger      *Logger

	// ROB-3: lastAccess tracks when this manager was last used (for LRU eviction).
	lastAccess atomic.Int64 // unix timestamp

	// ROB-CRIT-2: Parent context for all proactive refresh operations.
	// Canceled by Stop() so in-flight refreshes are interrupted immediately
	// instead of running for up to 30 seconds during shutdown.
	ctx    context.Context
	cancel context.CancelFunc

	// Proactive refresh — protected by timerMu
	timerMu            sync.Mutex
	refreshMargin      float64       // fraction of lifetime at which to refresh (default 0.80)
	minRefreshInterval time.Duration // minimum interval between refreshes (default 10s)
	persistInterval    time.Duration // periodic persist interval (default 5m)
	refreshTimer       *time.Timer
	persistTimer       *time.Timer   // periodic re-persist of in-memory token
	retryCount         uint // consecutive failures for exponential backoff
	stopped            bool

	// ROB-4: callbackWg tracks in-flight timer callbacks so Stop() can wait
	// for them to complete. Without this, a callback that already fired but
	// hasn't finished could outlive Stop() and call PersistToken after cleanup.
	callbackWg sync.WaitGroup
}

// TokenManagerConfig configures a TokenManager.
type TokenManagerConfig struct {
	Refresher          Refresher
	PersistDir         string
	CacheKey           string
	Logger             *Logger
	RefreshMargin      float64       // 0.80 = refresh at 80% of lifetime
	MinRefreshInterval time.Duration // minimum 10s between refreshes
	PersistInterval    time.Duration // periodic re-persist interval (default 5m)
}

// NewTokenManager creates a new TokenManager.
func NewTokenManager(cfg TokenManagerConfig) *TokenManager {
	if cfg.RefreshMargin <= 0 || cfg.RefreshMargin >= 1 {
		cfg.RefreshMargin = 0.80
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = 10 * time.Second
	}
	if cfg.PersistInterval <= 0 {
		cfg.PersistInterval = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	tm := &TokenManager{
		refresher:          cfg.Refresher,
		persistDir:         cfg.PersistDir,
		cacheKey:           cfg.CacheKey,
		logger:             cfg.Logger,
		refreshMargin:      cfg.RefreshMargin,
		minRefreshInterval: cfg.MinRefreshInterval,
		persistInterval:    cfg.PersistInterval,
		ctx:                ctx,
		cancel:             cancel,
	}
	tm.lastAccess.Store(time.Now().Unix())
	return tm
}

// SetInitialToken sets the initial token (from persistence or fresh auth).
// Also starts the proactive refresh timer and periodic persist watchdog.
func (m *TokenManager) SetInitialToken(idToken, refreshToken string, expiry time.Time) {
	entry := &tokenEntry{
		idToken:      idToken,
		refreshToken: refreshToken,
		expiry:       expiry,
		obtainedAt:   time.Now(),
	}
	m.current.Store(entry)
	m.scheduleProactiveRefresh(entry)
	m.startPersistWatchdog()
}

// GetToken returns the current token. Lock-free, nanosecond-level.
// Returns empty strings if no token is available.
func (m *TokenManager) GetToken() (idToken string, expiry time.Time, ok bool) {
	entry := m.current.Load()
	if entry == nil {
		return "", time.Time{}, false
	}
	m.lastAccess.Store(time.Now().Unix()) // ROB-3: track for LRU eviction
	return entry.idToken, entry.expiry, true
}

// LastAccess returns when this manager was last used (for LRU eviction).
func (m *TokenManager) LastAccess() time.Time {
	ts := m.lastAccess.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// SetRefresher replaces the refresher config (Provider, TLSConfig, ExtraParams).
// ROB-2: Called when a new request arrives with potentially updated kubeconfig
// settings (rotated client secret, changed CA cert, modified extra params).
// The singleflight in Refresh reads the refresher under refresherMu, so the
// next refresh after SetRefresher uses the new config.
func (m *TokenManager) SetRefresher(r Refresher) {
	m.refresherMu.Lock()
	m.refresher = r
	m.refresherMu.Unlock()
}

// HasToken returns whether a token is currently held.
func (m *TokenManager) HasToken() bool {
	return m.current.Load() != nil
}

// IsExpired returns whether the current token is expired.
func (m *TokenManager) IsExpired() bool {
	entry := m.current.Load()
	if entry == nil {
		return true
	}
	return time.Now().After(entry.expiry)
}

// Refresh performs a token refresh, coalesced via singleflight.
// Multiple concurrent callers get the same result.
//
// ROB-CRIT-1: The singleflight closure uses m.ctx (the TokenManager's lifecycle
// context) with its own 30s timeout, NOT the caller's context. This ensures:
// 1. Individual caller cancellation doesn't abort the refresh for all waiters
//    (e.g., if the first caller has a 2s SLA timeout, others still get the result)
// 2. Stop() can cancel in-flight refreshes via m.cancel() (B4 fix), preventing
//    30s hangs during shutdown that cause "deadline exceeded, forcing exit"
func (m *TokenManager) Refresh(ctx context.Context) (idToken string, expiry time.Time, err error) {
	v, sErr, _ := m.group.Do("refresh", func() (any, error) {
		entry := m.current.Load()
		if entry == nil {
			return nil, fmt.Errorf("no token to refresh")
		}

		// B3: If refresh token is empty, return a permanent error immediately.
		// This prevents infinite retry loops when the daemon loads a corrupt
		// persist file that has no refresh token.
		if entry.refreshToken == "" {
			return nil, &permanentRefreshError{reason: "refresh token is empty, re-authentication required"}
		}

		// ROB-CRIT-1 + B4: Use m.ctx as parent so:
		// - Caller cancellation doesn't affect the in-flight refresh
		// - Stop() (which cancels m.ctx) interrupts the refresh promptly
		refreshCtx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()

		// ROB-2: Snapshot the refresher under lock so SetRefresher can update
		// it concurrently (e.g., rotated client secret from a new request).
		m.refresherMu.Lock()
		refresher := m.refresher
		m.refresherMu.Unlock()

		newID, newRT, newExpiry, err := refresher.Refresh(refreshCtx, entry.refreshToken)
		if err != nil {
			// Classify OIDC provider errors as permanent when the refresh token
			// is revoked/expired. Without this, the daemon retries indefinitely
			// with exponential backoff instead of marking NEEDS_LOGIN.
			errStr := err.Error()
			if strings.Contains(errStr, "invalid_grant") || strings.Contains(errStr, "token has been revoked") {
				return nil, &permanentRefreshError{reason: fmt.Sprintf("refresh token revoked: %v", err)}
			}
			return nil, fmt.Errorf("refresh failed: %w", err)
		}

		newEntry := &tokenEntry{
			idToken:      newID,
			refreshToken: newRT,
			expiry:       newExpiry,
			obtainedAt:   time.Now(),
		}
		m.current.Store(newEntry)

		// Persist immediately (best-effort, failure is not fatal)
		if pErr := PersistToken(m.persistDir, m.cacheKey, newID, newRT); pErr != nil {
			m.logger.Warnf("persist after refresh failed: %v", pErr)
		}

		// Reset retry counter and reschedule proactive refresh
		m.timerMu.Lock()
		m.retryCount = 0
		m.timerMu.Unlock()
		m.scheduleProactiveRefresh(newEntry)

		m.logger.Infof("token refreshed, expires at %s", newExpiry.Format(time.RFC3339))
		return newEntry, nil
	})
	if sErr != nil {
		return "", time.Time{}, sErr
	}
	entry := v.(*tokenEntry)
	return entry.idToken, entry.expiry, nil
}

// scheduleProactiveRefresh sets a timer to refresh before the token expires.
func (m *TokenManager) scheduleProactiveRefresh(entry *tokenEntry) {
	m.timerMu.Lock()
	defer m.timerMu.Unlock()

	if m.stopped {
		return
	}
	if m.refreshTimer != nil {
		if m.refreshTimer.Stop() {
			// Timer was stopped before firing — the callback won't run,
			// so release its WaitGroup slot.
			m.callbackWg.Done()
		}
	}

	lifetime := time.Until(entry.expiry)
	if lifetime <= 0 {
		return
	}

	delay := time.Duration(float64(lifetime) * m.refreshMargin)
	if delay < m.minRefreshInterval {
		delay = m.minRefreshInterval
	}

	m.callbackWg.Add(1)
	m.refreshTimer = time.AfterFunc(delay, func() {
		defer m.callbackWg.Done()
		// SEC-CRIT-1: Recover panics in timer callbacks. Unlike handleConnection
		// (which has its own recover), timer goroutines are unprotected — a panic
		// here (e.g., nil pointer in gooidc.NewProvider, malformed JWT) would
		// crash the entire daemon, losing all in-memory tokens.
		defer func() {
			if r := recover(); r != nil {
				m.logger.Errorf("panic in proactive refresh (recovered): %v", r)
			}
		}()
		m.logger.Infof("proactive refresh triggered (token expires in %s)", time.Until(entry.expiry).Round(time.Second))
		// B4: Check if Stop() was called before doing work.
		if m.ctx.Err() != nil {
			return
		}
		// ROB-CRIT-2: Use m.ctx as parent so Stop() cancels in-flight refreshes
		// immediately instead of blocking shutdown for up to 30 seconds.
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		if _, _, err := m.Refresh(ctx); err != nil {
			m.logger.Warnf("proactive refresh failed: %v", err)
			// B3: Don't retry permanent errors (empty refresh token, revoked).
			if IsPermanentRefreshError(err) {
				m.logger.Warnf("permanent refresh error, not scheduling retry: %v", err)
				return
			}
			m.scheduleRetry(entry)
		}
	})
}

// scheduleRetry retries with exponential backoff after a failed proactive refresh.
// Starts at 1s, doubles each attempt, capped at 30s.
func (m *TokenManager) scheduleRetry(entry *tokenEntry) {
	m.timerMu.Lock()
	defer m.timerMu.Unlock()

	if m.stopped {
		return
	}

	// Release old timer's WaitGroup slot if it hasn't fired yet.
	// scheduleRetry is typically called from within a callback (old timer already
	// fired, so Stop returns false — no Done needed). But if scheduleProactiveRefresh
	// concurrently set a NEW timer between the callback firing and this lock acquisition,
	// m.refreshTimer points to that new timer. Stop returns true → we release its
	// Add(1) slot. The currently-executing callback's slot is released by its own
	// defer callbackWg.Done() at the top of the callback closure.
	if m.refreshTimer != nil {
		if m.refreshTimer.Stop() {
			m.callbackWg.Done()
		}
	}

	m.retryCount++
	retryCount := m.retryCount

	remaining := time.Until(entry.expiry)
	if remaining <= 0 {
		m.logger.Warnf("token expired and refresh failed, re-authentication required")
		return
	}

	// Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
	// ROB-2: Cap shift amount to prevent int64 overflow. time.Second is ~2^30,
	// so shifting by more than 33 overflows int64 and produces a negative duration
	// that bypasses the 30s cap below. Cap at 5 (32s) since anything above 30s
	// gets clamped anyway.
	shift := retryCount - 1
	if shift > 5 {
		shift = 5
	}
	delay := time.Second << shift
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	// ROB-CRIT-2: Add jitter (±25%) to prevent thundering herd when multiple
	// managers all fail simultaneously (VPN disconnect, provider outage).
	jitter := time.Duration(rand.Int63n(int64(delay) / 2)) // [0, delay/2)
	delay = delay/2 + delay/4 + jitter                     // [0.75*delay, 1.25*delay)
	// Don't delay beyond token expiry
	if delay > remaining {
		delay = remaining
	}

	m.callbackWg.Add(1)
	m.refreshTimer = time.AfterFunc(delay, func() {
		defer m.callbackWg.Done()
		defer func() {
			if r := recover(); r != nil {
				m.logger.Errorf("panic in retry refresh (recovered): %v", r)
			}
		}()
		m.logger.Infof("retry proactive refresh (attempt %d, backoff %s)", retryCount, delay.Round(time.Millisecond))
		// B4: Check if Stop() was called before doing work.
		if m.ctx.Err() != nil {
			return
		}
		ctx, cancel := context.WithTimeout(m.ctx, 30*time.Second)
		defer cancel()
		if _, _, err := m.Refresh(ctx); err != nil {
			m.logger.Warnf("retry refresh failed: %v", err)
			// B3: Don't retry permanent errors.
			if IsPermanentRefreshError(err) {
				m.logger.Warnf("permanent refresh error, giving up: %v", err)
				return
			}
			currentEntry := m.current.Load()
			if currentEntry != nil {
				m.scheduleRetry(currentEntry)
			}
		}
	})
}

// startPersistWatchdog starts a periodic timer that re-writes the in-memory
// token to disk. This closes the vulnerability window where a corrupted persist
// file survives until the next proactive refresh (which can be 24+ minutes
// with long-lived tokens). The watchdog fires every persistInterval (default
// 5 minutes), ensuring corruption is healed quickly regardless of token lifetime.
func (m *TokenManager) startPersistWatchdog() {
	m.timerMu.Lock()
	defer m.timerMu.Unlock()

	if m.stopped {
		return
	}
	// Don't start if already running (e.g., called multiple times).
	if m.persistTimer != nil {
		return
	}

	m.callbackWg.Add(1)
	m.persistTimer = time.AfterFunc(m.persistInterval, m.persistWatchdogCallback)
}

func (m *TokenManager) persistWatchdogCallback() {
	defer m.callbackWg.Done()
	defer func() {
		if r := recover(); r != nil {
			m.logger.Errorf("panic in persist watchdog (recovered): %v", r)
		}
	}()

	// Always reschedule first, before any early returns. If we return without
	// rescheduling, the watchdog dies permanently and can never heal a corrupt
	// persist file.
	defer func() {
		m.timerMu.Lock()
		defer m.timerMu.Unlock()
		if m.stopped || m.ctx.Err() != nil {
			return
		}
		m.callbackWg.Add(1)
		m.persistTimer = time.AfterFunc(m.persistInterval, m.persistWatchdogCallback)
	}()

	if m.ctx.Err() != nil {
		return
	}

	entry := m.current.Load()
	if entry == nil {
		return
	}

	// Don't persist empty tokens — this would overwrite a deleted corrupt
	// file with a new empty-token file, which is equally useless.
	if entry.idToken == "" && entry.refreshToken == "" {
		return
	}

	if err := PersistToken(m.persistDir, m.cacheKey, entry.idToken, entry.refreshToken); err != nil {
		m.logger.Warnf("persist watchdog failed: %v", err)
	} else {
		m.logger.Infof("persist watchdog wrote token for %s", m.cacheKey)
	}
}

// Stop stops the proactive refresh timer and waits for in-flight callbacks.
// Safe to call multiple times.
//
// ROB-4: After stopping the timer, waits for any already-fired callback to
// complete. This ensures no refresh is in progress when Stop returns, so
// the caller can safely persist the final token state.
func (m *TokenManager) Stop() {
	m.timerMu.Lock()
	if m.stopped {
		m.timerMu.Unlock()
		return
	}
	m.stopped = true
	// ROB-CRIT-2: Cancel the parent context so in-flight proactive refreshes
	// are interrupted immediately. Without this, callbackWg.Wait() below could
	// block for up to 30 seconds per in-flight refresh during shutdown.
	m.cancel()
	if m.refreshTimer != nil {
		if m.refreshTimer.Stop() {
			// Timer stopped before firing — callback won't run, release its slot.
			m.callbackWg.Done()
		}
		// If Stop returned false, the callback already fired and is running.
		// callbackWg.Wait below will wait for it (now fast due to canceled ctx).
	}
	if m.persistTimer != nil {
		if m.persistTimer.Stop() {
			m.callbackWg.Done()
		}
	}
	m.timerMu.Unlock()

	// Wait for any in-flight timer callbacks to finish.
	// Must be outside timerMu to avoid deadlock (callbacks acquire timerMu).
	m.callbackWg.Wait()
}

// CurrentRefreshToken returns the current refresh token for persistence.
func (m *TokenManager) CurrentRefreshToken() string {
	entry := m.current.Load()
	if entry == nil {
		return ""
	}
	return entry.refreshToken
}
