package shim

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// envWhitelist is the set of environment variables passed to the daemon child.
// Everything else is stripped. This prevents leaking secrets, locks, or
// behavior-altering vars from the parent into a long-running daemon.
var envWhitelist = []string{
	// Core
	"HOME", "USER", "LOGNAME", "PATH", "SHELL",
	// Linux
	"XDG_RUNTIME_DIR",
	// Windows
	"USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP",
	"SystemRoot", "APPDATA", "HOMEDRIVE", "HOMEPATH",
	// Locale
	"LANG", "LC_ALL", "LC_CTYPE",
	// Network (OIDC provider connectivity)
	"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
	"https_proxy", "http_proxy", "no_proxy",
}

// sanitizedEnv returns a minimal environment for the daemon child process,
// containing only whitelisted variables from the parent environment.
func sanitizedEnv() []string {
	env := make([]string, 0, len(envWhitelist))
	for _, key := range envWhitelist {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}

// autoStartDaemonCommon implements the shared AutoStartDaemon logic.
// preCleanup is platform-specific: Unix removes stale socket files,
// Windows is nil (named pipes are kernel-managed).
//
// B6: Uses atomic os.Mkdir as a guard to prevent thundering herd. When 100
// concurrent shims detect "no daemon", only one should fork a new daemon
// process. The others wait for the socket to become available.
func autoStartDaemonCommon(runtimeDir string, preCleanup func(runtimeDir string) error) error {
	addr := daemon.TransportAddress(runtimeDir)

	// Check if a daemon is already listening.
	if daemon.TransportProbeAlive(addr, 2*time.Second) {
		return nil
	}

	// Platform-specific stale cleanup (Unix: remove stale socket file).
	if preCleanup != nil {
		if err := preCleanup(runtimeDir); err != nil {
			return err
		}
	}

	// Ensure runtimeDir exists before creating the .starting guard.
	// On a fresh system, runtimeDir may not exist yet. Without this,
	// os.Mkdir(.starting) fails with ENOENT (not EEXIST) and the guard
	// is bypassed, allowing thundering herd.
	if err := os.Mkdir(runtimeDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create runtime dir %s: %w", runtimeDir, err)
	}

	// B6: Atomic mkdir guard to prevent thundering herd.
	// os.Mkdir is atomic: exactly one goroutine/process succeeds, all others
	// get EEXIST. This is NOT a file lock (P2 compliant) — it's a one-shot
	// atomic filesystem operation with automatic staleness detection.
	startingDir := filepath.Join(runtimeDir, ".starting")
	if err := os.Mkdir(startingDir, 0700); err != nil {
		if os.IsExist(err) {
			// Another shim is already starting the daemon.
			// Check if the .starting dir is stale (crashed shim).
			if info, statErr := os.Stat(startingDir); statErr == nil {
				if time.Since(info.ModTime()) > 10*time.Second {
					// Stale — the shim that created it probably crashed.
					os.Remove(startingDir)
					// Retry the mkdir (recursive call would be complex, just fall through)
					if mkErr := os.Mkdir(startingDir, 0700); mkErr != nil {
						// Another shim beat us to the retry — just wait for daemon.
						return waitForReady(addr, 10, 100*time.Millisecond, 500*time.Millisecond)
					}
					// We won the retry — fall through to fork.
					goto forkDaemon
				}
			}
			// Not stale — wait for the winner to finish starting the daemon.
			return waitForReady(addr, 10, 100*time.Millisecond, 500*time.Millisecond)
		}
		// Unexpected mkdir error (permission denied, disk full, etc.) —
		// fail rather than silently forking without the guard.
		return fmt.Errorf("auto-start guard: mkdir %s: %w", startingDir, err)
	}

forkDaemon:
	// Clean up the guard dir when we're done (success or failure).
	defer os.Remove(startingDir)

	// Find our own binary path.
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("eval symlinks: %w", err)
	}

	// Fork the daemon process.
	cmd := exec.Command(exePath, "daemon", "start", "--foreground")
	cmd.SysProcAttr = daemonSysProcAttr()
	cmd.Env = sanitizedEnv()
	cmd.Dir = runtimeDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Stdin = nil

	// Prevent parent's non-Go fds (flock locks, leaked sockets, etc.)
	// from being inherited by the daemon child. CLOEXEC fds are closed
	// by the kernel during exec; parent's fds remain usable.
	setCloseOnExecAboveStderr()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start daemon process: %w", err)
	}

	// Don't wait for the daemon — release to avoid zombie.
	if err := cmd.Process.Release(); err != nil {
		_ = err
	}

	// Wait for daemon to become available with jittered backoff.
	if err := waitForReady(addr, 5, 100*time.Millisecond, 500*time.Millisecond); err != nil {
		return fmt.Errorf("daemon did not start: %w", err)
	}

	return nil
}

// waitForReady polls the transport address until the daemon is connectable.
func waitForReady(addr string, maxRetries int, minDelay, maxDelay time.Duration) error {
	for i := 0; i < maxRetries; i++ {
		// ROB-MED-4: Guard against panic if maxDelay <= minDelay.
		delay := minDelay
		if maxDelay > minDelay {
			delay += time.Duration(rand.Int63n(int64(maxDelay - minDelay)))
		}
		time.Sleep(delay)

		if daemon.TransportProbeAlive(addr, 2*time.Second) {
			return nil
		}
	}
	return fmt.Errorf("daemon at %s not ready after %d retries", addr, maxRetries)
}
