package chaos

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// deleteSocket removes the daemon's transport endpoint to test auto-start recovery.
//
// On Unix: removes the socket file, leaving the daemon running but unreachable.
// On Windows: named pipes are kernel objects (not files), so os.Remove doesn't work.
// Instead, we kill the daemon process — the pipe is destroyed when the last handle closes.
func (e *Engine) deleteSocket(ctx context.Context) (ChaosEvent, error) {
	event := ChaosEvent{
		Timestamp: time.Now(),
		Type:      "delete_socket",
	}

	oldPID := int(e.daemonPID.Load())

	if runtime.GOOS == "windows" {
		// Named pipes are kernel-managed; can't be removed via filesystem.
		// Kill the daemon instead — the pipe dies with the process.
		return e.deleteSocketWindows(ctx, event, oldPID)
	}

	return e.deleteSocketUnix(ctx, event, oldPID)
}

// deleteSocketUnix removes the Unix socket file and measures recovery.
func (e *Engine) deleteSocketUnix(ctx context.Context, event ChaosEvent, oldPID int) (ChaosEvent, error) {
	err := os.Remove(e.socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			event.Description = "delete_socket: socket already gone"
			return event, nil
		}
		event.Description = fmt.Sprintf("delete_socket: remove failed: %v", err)
		return event, err
	}

	event.Description = fmt.Sprintf("delete_socket: removed socket (old PID %d)", oldPID)

	// Measure recovery: wait for new socket to become connectable
	// (triggered by next kubectl call via auto-start)
	event = e.measureRecovery(ctx, event)

	// Kill orphaned old daemon to prevent PID accumulation.
	// The old daemon is unreachable (socket inode deleted) but still alive.
	if oldPID > 0 {
		proc, err := os.FindProcess(oldPID)
		if err == nil {
			if processIsKubeloginDaemon(oldPID) {
				_ = proc.Signal(os.Kill)
				event.Description += fmt.Sprintf(", killed orphaned PID %d", oldPID)
			}
		}
	}

	return event, nil
}

// deleteSocketWindows kills the daemon process on Windows.
// Named pipes are destroyed when the last handle closes, so killing the
// daemon is equivalent to deleting the transport endpoint.
func (e *Engine) deleteSocketWindows(ctx context.Context, event ChaosEvent, oldPID int) (ChaosEvent, error) {
	if oldPID <= 0 {
		event.Description = "delete_socket: no known daemon PID, skipping"
		return event, nil
	}

	// Signal orchestrator that this kill is intentional (suppress health alerts)
	e.intentionalKill.Store(true)
	defer func() {
		time.AfterFunc(5*time.Second, func() {
			e.intentionalKill.Store(false)
		})
	}()

	proc, err := os.FindProcess(oldPID)
	if err != nil {
		event.Description = fmt.Sprintf("delete_socket: FindProcess(%d) failed: %v", oldPID, err)
		return event, nil
	}

	if err := proc.Signal(os.Kill); err != nil {
		event.Description = fmt.Sprintf("delete_socket: kill PID %d failed: %v (may already be dead)", oldPID, err)
		return event, nil
	}

	event.Description = fmt.Sprintf("delete_socket: killed daemon PID %d (named pipe destroyed)", oldPID)

	event = e.measureRecovery(ctx, event)
	return event, nil
}

// measureRecovery waits for the daemon to become connectable again.
func (e *Engine) measureRecovery(ctx context.Context, event ChaosEvent) ChaosEvent {
	recoveryStart := time.Now()
	recovered := false
	for i := 0; i < 60; i++ { // up to 30s
		select {
		case <-ctx.Done():
			return event
		case <-time.After(500 * time.Millisecond):
		}

		conn, err := daemon.TransportDial(daemon.TransportAddress(e.runtimeDir), 1*time.Second)
		if err == nil {
			conn.Close()
			recovered = true
			break
		}
	}

	event.RecoveryTime = time.Since(recoveryStart)
	if recovered {
		event.Description += fmt.Sprintf(", recovered in %s", event.RecoveryTime)
	} else {
		event.Description += ", recovery timeout (30s)"
	}
	return event
}

// processIsKubeloginDaemon checks if the given PID is a kubelogin-daemon process.
func processIsKubeloginDaemon(pid int) bool {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return false
		}
		return strings.Contains(string(data), "kubelogin-daemon")
	case "windows":
		out, err := exec.Command("tasklist", "/FI",
			fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "kubelogin-daemon")
	default: // macOS
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "kubelogin-daemon")
	}
}
