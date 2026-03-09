package chaos

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
)

// Engine coordinates chaos fault injection with a global cooldown mutex.
type Engine struct {
	cfg    config.ChaosConfig
	rng    *rand.Rand
	logger *logging.Logger
	recorder *metrics.Recorder

	actions []*ChaosAction

	mu            sync.Mutex
	lastChaosTime time.Time
	// S2: Track last corrupt/kill times for mutual exclusion window.
	// After corrupt_token_files fires, kill_daemon is delayed by 2 minutes
	// (and vice versa) to give the daemon time to detect corruption, refresh,
	// and persist the new token. Without this, a corrupt→kill overlap is an
	// unrecoverable double-fault.
	lastCorruptTime time.Time
	lastKillTime    time.Time

	// Shared state from orchestrator
	intentionalKill *atomic.Bool
	daemonPID       *atomic.Int64
	socketPath      string
	runtimeDir      string
}

// ChaosAction represents a single chaos fault type.
type ChaosAction struct {
	name     string
	cfg      config.ChaosTypeConfig
	execute  func(ctx context.Context) (ChaosEvent, error)
}

// ChaosEvent records a chaos injection event.
type ChaosEvent struct {
	Timestamp    time.Time
	Type         string
	Description  string
	DurationHeld time.Duration
	RecoveryTime time.Duration
}

// New creates a new chaos engine.
func New(
	cfg config.ChaosConfig,
	rng *rand.Rand,
	logger *logging.Logger,
	recorder *metrics.Recorder,
	intentionalKill *atomic.Bool,
	daemonPID *atomic.Int64,
	socketPath, runtimeDir string,
) *Engine {
	e := &Engine{
		cfg:             cfg,
		rng:             rng,
		logger:          logger,
		recorder:        recorder,
		intentionalKill: intentionalKill,
		daemonPID:       daemonPID,
		socketPath:      socketPath,
		runtimeDir:      runtimeDir,
	}

	// Register enabled chaos actions
	if cfg.KillDaemon.Enabled {
		e.actions = append(e.actions, &ChaosAction{
			name:    "kill_daemon",
			cfg:     cfg.KillDaemon,
			execute: e.killDaemon,
		})
	}
	if cfg.DeleteSocket.Enabled {
		e.actions = append(e.actions, &ChaosAction{
			name:    "delete_socket",
			cfg:     cfg.DeleteSocket,
			execute: e.deleteSocket,
		})
	}
	if cfg.CorruptTokenFiles.Enabled {
		e.actions = append(e.actions, &ChaosAction{
			name:    "corrupt_token_files",
			cfg:     cfg.CorruptTokenFiles,
			execute: e.corruptTokenFiles,
		})
	}
	if cfg.FillConnections.Enabled {
		e.actions = append(e.actions, &ChaosAction{
			name:    "fill_connections",
			cfg:     cfg.FillConnections,
			execute: e.fillConnections,
		})
	}
	if cfg.FillDisk.Enabled {
		e.actions = append(e.actions, &ChaosAction{
			name:    "fill_disk",
			cfg:     cfg.FillDisk,
			execute: e.fillDisk,
		})
	}

	return e
}

// Run starts all chaos timers and blocks until context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	if !e.cfg.Enabled || len(e.actions) == 0 {
		<-ctx.Done()
		return nil
	}

	// Initial stability period — no chaos during ramp-up
	e.logger.Infof("chaos: waiting %s stability period", e.cfg.InitialStabilityPeriod)
	select {
	case <-time.After(e.cfg.InitialStabilityPeriod):
	case <-ctx.Done():
		return nil
	}
	e.logger.Info("chaos: stability period complete, starting fault injection")

	errCh := make(chan error, len(e.actions))
	var wg sync.WaitGroup

	for _, action := range e.actions {
		wg.Add(1)
		go func(a *ChaosAction) {
			defer wg.Done()
			if err := e.chaosLoop(ctx, a); err != nil {
				errCh <- err
			}
		}(action)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) chaosLoop(ctx context.Context, a *ChaosAction) error {
	for {
		interval := e.randomDuration(a.cfg.IntervalMin, a.cfg.IntervalMax)
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return nil
		}

		// Global cooldown: acquire mutex, enforce minimum gap
		e.mu.Lock()
		if elapsed := time.Since(e.lastChaosTime); elapsed < e.cfg.GlobalCooldown {
			remaining := e.cfg.GlobalCooldown - elapsed
			e.mu.Unlock()
			select {
			case <-time.After(remaining):
			case <-ctx.Done():
				return nil
			}
			e.mu.Lock()
		}
		e.lastChaosTime = time.Now()

		// S2: Mutual exclusion between corrupt_token_files and kill/restart events.
		// The daemon's persist watchdog re-writes the in-memory token to disk every
		// 5 minutes. If kill/restart happens before the watchdog fires, the new
		// daemon finds a corrupt persist file and has no token. The exclusion window
		// must be > persist watchdog interval (5 min) + margin.
		const exclusionWindow = 6 * time.Minute
		// S2: delete_socket causes daemon restart (same as kill_daemon), so
		// both kill_daemon and delete_socket must be excluded after corrupt_token_files.
		isKillLike := a.name == "kill_daemon" || a.name == "delete_socket"
		if isKillLike && !e.lastCorruptTime.IsZero() && time.Since(e.lastCorruptTime) < exclusionWindow {
			e.logger.Infof("chaos: skipping %s (corrupt_token_files fired %s ago, exclusion window %s)", a.name, time.Since(e.lastCorruptTime).Round(time.Second), exclusionWindow)
			e.mu.Unlock()
			continue
		}
		if a.name == "corrupt_token_files" && !e.lastKillTime.IsZero() && time.Since(e.lastKillTime) < exclusionWindow {
			e.logger.Infof("chaos: skipping corrupt_token_files (kill/delete_socket fired %s ago, exclusion window %s)", time.Since(e.lastKillTime).Round(time.Second), exclusionWindow)
			e.mu.Unlock()
			continue
		}

		e.logger.Infof("chaos: executing %s", a.name)

		// Timeout chaos action execution to prevent mutex starvation
		actionCtx, actionCancel := context.WithTimeout(ctx, 2*time.Minute)
		event, err := a.execute(actionCtx)
		actionCancel()

		// S2: Record corrupt/kill times for mutual exclusion tracking.
		if a.name == "corrupt_token_files" {
			e.lastCorruptTime = time.Now()
		} else if a.name == "kill_daemon" || a.name == "delete_socket" {
			e.lastKillTime = time.Now()
		}

		e.recorder.RecordChaos(event.Timestamp, event.Type, event.Description,
			event.DurationHeld, event.RecoveryTime)
		e.recorder.RecordTimeline("chaos", event.Description)
		e.mu.Unlock()

		if err != nil {
			e.logger.Errorf("chaos %s execution error: %v", a.name, err)
			// Non-fatal: log and continue
		}
	}
}

func (e *Engine) randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	return min + time.Duration(e.rng.Int63n(int64(delta)))
}
