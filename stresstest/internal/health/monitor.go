package health

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
)

// Monitor polls the daemon for health status.
type Monitor struct {
	cfg        config.HealthConfig
	logger     *logging.Logger
	recorder   *metrics.Recorder
	socketPath string
	runtimeDir string

	// Shared state from orchestrator
	daemonPID       *atomic.Int64
	daemonRestarts  *atomic.Int64
	intentionalKill *atomic.Bool
	phase           atomic.Int32 // workload.Phase
}

// New creates a new health monitor.
func New(
	cfg config.HealthConfig,
	logger *logging.Logger,
	recorder *metrics.Recorder,
	socketPath, runtimeDir string,
	daemonPID *atomic.Int64,
	daemonRestarts *atomic.Int64,
	intentionalKill *atomic.Bool,
) *Monitor {
	return &Monitor{
		cfg:             cfg,
		logger:          logger,
		recorder:        recorder,
		socketPath:      socketPath,
		runtimeDir:      runtimeDir,
		daemonPID:       daemonPID,
		daemonRestarts:  daemonRestarts,
		intentionalKill: intentionalKill,
	}
}

// SetPhase sets the current workload phase (called by generator).
func (m *Monitor) SetPhase(phase int32) {
	m.phase.Store(phase)
}

// Run starts the health monitoring loop.
func (m *Monitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	var consecutiveFailures int

	for {
		select {
		case <-ticker.C:
			ts := time.Now()

			// Idle-aware probing: during quiescent phases, use process-only checks
			// to avoid resetting the daemon's idle timer.
			var (
				pid          int
				memoryRSS    int64
				responsive   bool
				responseTime time.Duration
				probeMode    string
				tokenCount   int
				uptimeS      int64
			)

			isQuiescent := m.phase.Load() == 2 // PhaseQuiescent
			if isQuiescent && m.cfg.IdleAwareProbing {
				probeMode = "process"
				pid, memoryRSS, responsive = m.probeProcessOnly()
			} else {
				probeMode = "socket"
				pid, memoryRSS, tokenCount, uptimeS, responsive, responseTime = m.probeSocket()
			}

			m.recorder.RecordHealth(
				ts, pid, uptimeS, memoryRSS, tokenCount,
				responsive, responseTime.Milliseconds(), probeMode,
			)

			if !responsive {
				if m.intentionalKill.Load() {
					consecutiveFailures = 0
					continue
				}
				// During quiescent phase, daemon death is expected (idle timeout
				// or chaos kill). Don't count it as failure — the next kubectl
				// call in steady/burst will auto-start the daemon. Only escalate
				// unresponsive counters during active phases where recovery is
				// expected to happen promptly.
				if isQuiescent {
					continue
				}
				consecutiveFailures++
				failDur := time.Duration(consecutiveFailures) * m.cfg.PollInterval
				if failDur > m.cfg.HangThreshold {
					m.logger.Errorf("daemon unresponsive for %s", failDur)
					m.recorder.RecordTimeline("alert",
						fmt.Sprintf("daemon unresponsive for %s", failDur))
				}
				if m.cfg.ExitThreshold > 0 && failDur > m.cfg.ExitThreshold {
					return fmt.Errorf("daemon unresponsive for %s (exit threshold %s exceeded)",
						failDur, m.cfg.ExitThreshold)
				}
			} else {
				if consecutiveFailures >= 3 {
					m.recorder.RecordTimeline("recovery",
						fmt.Sprintf("recovered after %d failed polls", consecutiveFailures))
				}
				consecutiveFailures = 0

				// PID change detection
				if pid > 0 && pid != int(m.daemonPID.Load()) {
					old := m.daemonPID.Swap(int64(pid))
					if old > 0 {
						m.daemonRestarts.Add(1)
						m.recorder.RecordTimeline("restart",
							fmt.Sprintf("PID %d -> %d", old, pid))
						m.logger.Infof("daemon restart detected: PID %d -> %d", old, pid)
					} else {
						m.logger.Infof("initial daemon PID: %d", pid)
					}
				}

				// Memory checks
				if memoryRSS > 0 {
					rssMB := memoryRSS / (1024 * 1024)
					if rssMB > int64(m.cfg.MemoryKillMB) {
						m.logger.Errorf("daemon RSS %dMB exceeds kill threshold %dMB, aborting",
							rssMB, m.cfg.MemoryKillMB)
						return fmt.Errorf("daemon RSS %dMB exceeds kill threshold %dMB",
							rssMB, m.cfg.MemoryKillMB)
					}
					if rssMB > int64(m.cfg.MemoryWarnMB) {
						m.logger.Warnf("daemon RSS %dMB exceeds warning threshold %dMB",
							rssMB, m.cfg.MemoryWarnMB)
						m.recorder.RecordTimeline("memory_warn",
							fmt.Sprintf("RSS %dMB > warn %dMB", rssMB, m.cfg.MemoryWarnMB))
					}
				}
			}

		case <-ctx.Done():
			return nil
		}
	}
}

// probeSocket connects to the daemon socket and gets health info.
func (m *Monitor) probeSocket() (pid int, rss int64, tokenCount int, uptimeS int64, responsive bool, responseTime time.Duration) {
	start := time.Now()

	conn, err := daemon.TransportDial(daemon.TransportAddress(m.runtimeDir), 2*time.Second)
	if err != nil {
		return 0, 0, 0, 0, false, time.Since(start)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	nonce, err := os.ReadFile(filepath.Join(m.runtimeDir, "nonce"))
	if err != nil {
		return 0, 0, 0, 0, false, time.Since(start)
	}

	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
		Nonce:   string(nonce),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return 0, 0, 0, 0, false, time.Since(start)
	}

	var resp daemon.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return 0, 0, 0, 0, false, time.Since(start)
	}

	responseTime = time.Since(start)
	if resp.Status != "ok" {
		return 0, 0, 0, 0, false, responseTime
	}

	return resp.PID, 0, resp.TokenCount, int64(resp.UptimeSeconds), true, responseTime
}

// probeProcessOnly checks daemon health via process-level checks only.
func (m *Monitor) probeProcessOnly() (pid int, rss int64, alive bool) {
	p := int(m.daemonPID.Load())
	if p <= 0 {
		return 0, 0, false
	}

	alive = processExists(p)
	if !alive {
		return p, 0, false
	}

	rss, _ = getProcessRSS(p)
	return p, rss, true
}
