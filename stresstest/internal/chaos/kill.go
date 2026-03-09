package chaos

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// killDaemon sends SIGKILL to the daemon process and measures recovery time.
func (e *Engine) killDaemon(ctx context.Context) (ChaosEvent, error) {
	event := ChaosEvent{
		Timestamp: time.Now(),
		Type:      "kill_daemon",
	}

	pid := int(e.daemonPID.Load())
	if pid <= 0 {
		event.Description = "kill_daemon: no known daemon PID, skipping"
		return event, nil
	}

	// Signal orchestrator that this kill is intentional (suppress health alerts)
	e.intentionalKill.Store(true)
	defer func() {
		// Clear after recovery measurement
		time.AfterFunc(5*time.Second, func() {
			e.intentionalKill.Store(false)
		})
	}()

	// Kill the daemon
	proc, err := os.FindProcess(pid)
	if err != nil {
		event.Description = fmt.Sprintf("kill_daemon: FindProcess(%d) failed: %v", pid, err)
		return event, err
	}

	if err := proc.Signal(os.Kill); err != nil {
		event.Description = fmt.Sprintf("kill_daemon: SIGKILL PID %d failed: %v", pid, err)
		return event, nil // daemon may already be dead
	}

	event.Description = fmt.Sprintf("kill_daemon: sent SIGKILL to PID %d", pid)

	// Measure recovery time: how long until socket accepts connections again
	recoveryStart := time.Now()
	recovered := false
	for i := 0; i < 60; i++ { // up to 30s
		select {
		case <-ctx.Done():
			return event, nil
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

	return event, nil
}
