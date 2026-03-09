package chaos

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
)

// fillConnections opens many connections to exhaust the daemon's connSem.
func (e *Engine) fillConnections(ctx context.Context) (ChaosEvent, error) {
	event := ChaosEvent{
		Timestamp: time.Now(),
		Type:      "fill_connections",
	}

	targetCount := e.cfg.FillConnections.TargetCount
	holdDuration := e.cfg.FillConnections.HoldDuration

	conns := make([]net.Conn, 0, targetCount)
	connected := 0
	rejected := 0

	for i := 0; i < targetCount; i++ {
		if ctx.Err() != nil {
			break
		}
		conn, err := daemon.TransportDial(daemon.TransportAddress(e.runtimeDir), 2*time.Second)
		if err != nil {
			rejected++
			continue
		}
		conns = append(conns, conn)
		connected++
	}

	event.Description = fmt.Sprintf("fill_connections: opened %d, rejected %d (target %d)",
		connected, rejected, targetCount)
	event.DurationHeld = holdDuration

	// Hold connections
	select {
	case <-time.After(holdDuration):
	case <-ctx.Done():
	}

	// Release all connections
	for _, conn := range conns {
		conn.Close()
	}

	// Measure recovery: can we connect again?
	recoveryStart := time.Now()
	for i := 0; i < 10; i++ {
		conn, err := daemon.TransportDial(daemon.TransportAddress(e.runtimeDir), 1*time.Second)
		if err == nil {
			conn.Close()
			event.RecoveryTime = time.Since(recoveryStart)
			event.Description += fmt.Sprintf(", recovered in %s", event.RecoveryTime)
			return event, nil
		}
		time.Sleep(500 * time.Millisecond)
	}

	event.RecoveryTime = time.Since(recoveryStart)
	event.Description += ", recovery timeout (5s)"
	return event, fmt.Errorf("fill_connections: daemon did not recover after 5s")
}
