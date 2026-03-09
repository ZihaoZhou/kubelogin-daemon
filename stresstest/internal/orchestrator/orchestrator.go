package orchestrator

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/ZihaoZhou/kubelogin-daemon/pkg/daemon"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/chaos"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/health"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/reaper"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/report"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/workload"
)

// Orchestrator coordinates all stress test subsystems.
type Orchestrator struct {
	cfg *config.Config

	db       *sql.DB
	logger   *logging.Logger
	recorder *metrics.Recorder
	rng      *rand.Rand

	gen      *workload.Generator
	chaosEng *chaos.Engine
	monitor  *health.Monitor
	rp       *reaper.Reaper
	reporter *report.Reporter
	tracker  *workload.ResourceTracker

	// Shared state
	daemonPID       atomic.Int64
	intentionalKill atomic.Bool
	interrupted     atomic.Bool
	daemonRestarts  atomic.Int64

	testRunID       string
	startTime       time.Time
	daemonBinaryHash string

	// Paths
	socketPath string
	runtimeDir string

	errCh chan error
	wg    sync.WaitGroup
}

// New creates a new Orchestrator.
func New(cfg *config.Config) *Orchestrator {
	return &Orchestrator{cfg: cfg}
}

// Run executes the full stress test.
func (o *Orchestrator) Run(ctx context.Context) error {
	o.startTime = time.Now()
	o.testRunID = uuid.New().String()

	// 1. Create output directory
	if err := os.MkdirAll(o.cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// 2. Init SQLite
	dbPath := filepath.Join(o.cfg.OutputDir, "stress.db")
	var err error
	o.db, err = metrics.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("init db: %w", err)
	}
	defer o.db.Close()

	// 3. Init logger
	logPath := filepath.Join(o.cfg.OutputDir, "stress-test.log")
	o.logger, err = logging.New(logPath, o.cfg.Verbose)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer o.logger.Close()

	o.logger.Infof("stress test starting: run_id=%s", o.testRunID)

	// 4. Init recorder
	o.recorder = metrics.NewRecorder(o.db, o.testRunID)
	defer o.recorder.Close()

	// 5. RNG seed
	if o.cfg.RNGSeed == 0 {
		o.cfg.RNGSeed = time.Now().UnixNano()
	}
	o.rng = rand.New(rand.NewSource(o.cfg.RNGSeed))
	o.logger.Infof("RNG seed: %d", o.cfg.RNGSeed)

	// 6. Resolve daemon binary
	if err := o.resolveDaemonBinary(); err != nil {
		return err
	}

	// 7. Resolve paths
	o.resolveRuntimePaths()
	o.logger.Infof("runtime dir: %s", o.runtimeDir)
	o.logger.Infof("transport address: %s", o.socketPath)

	// 8. Validate prerequisites
	if err := o.validateKubectl(); err != nil {
		return err
	}
	if err := o.validateNamespaceAccess(ctx); err != nil {
		return err
	}
	if err := o.validateDiskSpace(); err != nil {
		return err
	}

	// 8b. Clean up stale fill_disk files from previous crashed run
	o.cleanStaleFillFiles()

	// 9. Probe initial daemon state
	o.probeDaemon()

	// 10. Record timeline start
	o.recorder.RecordTimeline("start",
		fmt.Sprintf("stress test started: namespace=%s duration=%s", o.cfg.Namespace, o.cfg.Duration))

	// 11. Create subsystems
	executor := workload.NewKubectlExecutor(
		o.cfg.Namespace, o.cfg.Workload.KubeconfigContext,
		o.cfg.Workload.KubectlTimeout, o.logger)

	o.tracker = workload.NewResourceTracker(o.cfg.Workload.MaxResources)

	prober := workload.NewDirectSocketProber(
		o.socketPath, o.runtimeDir,
		o.cfg.Workload.DirectIPCWorkers,
		o.recorder, o.cfg.Workload.SLAThreshold)

	o.gen = workload.NewGenerator(
		o.cfg.Workload, o.rng, o.logger, executor, prober,
		o.tracker, o.recorder, o.cfg.ManagedByValue())

	o.chaosEng = chaos.New(
		o.cfg.Chaos, o.rng, o.logger, o.recorder,
		&o.intentionalKill, &o.daemonPID,
		o.socketPath, o.runtimeDir)

	o.monitor = health.New(
		o.cfg.Health, o.logger, o.recorder,
		o.socketPath, o.runtimeDir,
		&o.daemonPID, &o.daemonRestarts, &o.intentionalKill)

	o.rp = reaper.New(
		o.cfg.Reaper, o.cfg.Namespace, o.cfg.LabelSelector(),
		o.logger, o.recorder, executor, o.tracker)

	// Wire phase change callback
	o.gen.SetPhaseCallback(func(phase workload.Phase) {
		o.monitor.SetPhase(int32(phase))
	})

	// 12. Create deadline context
	testCtx, cancel := context.WithTimeout(ctx, o.cfg.Duration)
	defer cancel()

	// 13. Start subsystems (with panic recovery)
	o.errCh = make(chan error, 4)
	o.wg.Add(4)
	runSubsystem := func(name string, fn func(context.Context) error) {
		defer o.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				o.sendErr(fmt.Errorf("panic in %s: %v", name, r))
			}
		}()
		o.sendErr(fn(testCtx))
	}
	go runSubsystem("workload", o.gen.Run)
	go runSubsystem("chaos", o.chaosEng.Run)
	go runSubsystem("health", o.monitor.Run)
	go runSubsystem("reaper", o.rp.Run)

	o.logger.Info("all subsystems started")

	// 14. Wait for completion, interrupt, or critical subsystem error
	select {
	case <-testCtx.Done():
		// Normal completion or parent cancel
	case err := <-o.errCh:
		o.logger.Errorf("critical subsystem error: %v", err)
		o.interrupted.Store(true)
		cancel()
	}

	// 14b. Drain remaining errors
	for {
		select {
		case err := <-o.errCh:
			o.logger.Errorf("subsystem error (post-select): %v", err)
			o.interrupted.Store(true)
		default:
			goto drained
		}
	}
drained:

	// 15. Check if interrupted by signal
	if ctx.Err() != nil {
		o.interrupted.Store(true)
	}

	// 16. Graceful shutdown (60s deadline)
	o.logger.Info("shutting down subsystems...")
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
		o.logger.Info("all subsystems stopped")
	case <-time.After(60 * time.Second):
		o.logger.Warn("shutdown deadline exceeded, proceeding with report")
		o.interrupted.Store(true)
	}

	// 17. Copy daemon log (best-effort)
	o.copyDaemonLog()

	// 18. Record timeline end
	o.recorder.RecordTimeline("end",
		fmt.Sprintf("stress test completed: interrupted=%v", o.interrupted.Load()))

	// 19. Flush recorder
	o.recorder.Close()

	// 20. Generate report
	o.reporter = report.NewReporter(o.db, o.testRunID, o.cfg.Report.Percentiles)
	rpt := o.reporter.Generate()
	rpt.StartTime = o.startTime
	rpt.EndTime = time.Now()
	rpt.Duration = rpt.EndTime.Sub(rpt.StartTime).String()
	rpt.Namespace = o.cfg.Namespace
	rpt.RNGSeed = o.cfg.RNGSeed
	rpt.DaemonBinaryHash = o.daemonBinaryHash
	rpt.Interrupted = o.interrupted.Load()
	rpt.DaemonHealth.RestartCount = o.daemonRestarts.Load()
	rpt.ResourceManagement.OrphansAtEnd = int64(o.tracker.OrphansAtEnd())

	total, successes, failures, slaViol := o.gen.Stats()
	rpt.Summary.DaemonRestarts = o.daemonRestarts.Load()
	_ = total
	_ = successes
	_ = failures
	rpt.Summary.SLAViolations = slaViol

	rpt.Verdict, rpt.Issues = report.DetermineVerdict(rpt, o.cfg.Health.MemoryKillMB)

	if err := o.reporter.Write(rpt, o.cfg.OutputDir); err != nil {
		o.logger.Errorf("write report: %v", err)
	}

	// Print verdict
	o.logger.Infof("verdict: %s", rpt.Verdict)
	for _, issue := range rpt.Issues {
		o.logger.Infof("  - %s", issue)
	}

	fmt.Printf("\n=== Stress Test Complete ===\n")
	fmt.Printf("Verdict: %s\n", rpt.Verdict)
	fmt.Printf("Duration: %s\n", rpt.Duration)
	fmt.Printf("Total invocations: %d\n", rpt.Summary.TotalInvocations)
	fmt.Printf("SLO success rate: %.1f%%\n", rpt.Summary.SLOSuccessRate)
	fmt.Printf("Report: %s\n", filepath.Join(o.cfg.OutputDir, "report.json"))
	for _, issue := range rpt.Issues {
		fmt.Printf("  - %s\n", issue)
	}

	if rpt.Verdict == "FAIL" {
		return fmt.Errorf("stress test FAILED: %s", strings.Join(rpt.Issues, "; "))
	}
	return nil
}

func (o *Orchestrator) sendErr(err error) {
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		select {
		case o.errCh <- err:
		default:
		}
	}
}

func (o *Orchestrator) resolveDaemonBinary() error {
	daemonPath, err := exec.LookPath(o.cfg.DaemonBinary)
	if err != nil {
		return fmt.Errorf("daemon binary %q not found in PATH: %w", o.cfg.DaemonBinary, err)
	}

	f, err := os.Open(daemonPath)
	if err != nil {
		return fmt.Errorf("open daemon binary: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hash daemon binary: %w", err)
	}
	o.daemonBinaryHash = fmt.Sprintf("%x", h.Sum(nil))
	o.logger.Infof("daemon binary: %s (sha256: %s)", daemonPath, o.daemonBinaryHash[:16])

	return nil
}

func (o *Orchestrator) resolveRuntimePaths() {
	if o.cfg.RuntimeDir != "" {
		o.runtimeDir = o.cfg.RuntimeDir
	} else {
		// S1: Use daemon.RuntimeDir() directly instead of reimplementing.
		// The previous code used os.TempDir() and os.Getuid() which don't
		// match the daemon's stable path logic (stableTempDir=/tmp on Unix,
		// SID on Windows instead of UID).
		o.runtimeDir = daemon.RuntimeDir()
	}

	if o.cfg.SocketPath != "" {
		o.socketPath = o.cfg.SocketPath
	} else {
		o.socketPath = daemon.TransportAddress(o.runtimeDir)
	}
}

func (o *Orchestrator) validateKubectl() error {
	_, err := exec.LookPath("kubectl")
	if err != nil {
		return fmt.Errorf("kubectl not found in PATH: %w", err)
	}
	return nil
}

func (o *Orchestrator) validateNamespaceAccess(ctx context.Context) error {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "kubectl", "get", "pods",
		"--namespace", o.cfg.Namespace, "--no-headers")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("namespace access check failed for %q: %s\n%s",
			o.cfg.Namespace, err, string(out))
	}
	o.logger.Infof("namespace %q accessible", o.cfg.Namespace)
	return nil
}

func (o *Orchestrator) validateDiskSpace() error {
	// Best-effort check: try to stat the output dir
	info, err := os.Stat(o.cfg.OutputDir)
	if err != nil {
		return nil // will be caught later
	}
	if !info.IsDir() {
		return fmt.Errorf("output_dir %q is not a directory", o.cfg.OutputDir)
	}
	// Note: actual free space check would require platform-specific syscalls.
	// Logging a reminder instead.
	o.logger.Info("ensure output_dir has at least 3GB free space for 24h run")
	return nil
}

func (o *Orchestrator) probeDaemon() {
	conn, err := daemon.TransportDial(daemon.TransportAddress(o.runtimeDir), 2*time.Second)
	if err != nil {
		o.logger.Info("no daemon currently running (or socket unreachable)")
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Full health probe to get PID — without this, the health monitor's
	// probeProcessOnly() mode has no PID and reports perpetual unresponsive.
	nonce, err := os.ReadFile(filepath.Join(o.runtimeDir, "nonce"))
	if err != nil {
		o.logger.Info("daemon is already running (nonce unreadable, PID unknown)")
		return
	}
	req := daemon.Request{
		Version: daemon.ProtocolVersion,
		Command: "health",
		Nonce:   string(nonce),
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		o.logger.Info("daemon is already running (health probe failed, PID unknown)")
		return
	}
	var resp daemon.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		o.logger.Info("daemon is already running (health decode failed, PID unknown)")
		return
	}
	if resp.PID > 0 {
		o.daemonPID.Store(int64(resp.PID))
		o.logger.Infof("daemon is already running (PID %d)", resp.PID)
	} else {
		o.logger.Info("daemon is already running (PID not reported)")
	}
}

func (o *Orchestrator) copyDaemonLog() {
	src := filepath.Join(o.runtimeDir, "daemon.log")
	dst := filepath.Join(o.cfg.OutputDir, "daemon.log")

	in, err := os.Open(src)
	if err != nil {
		return // best-effort
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer out.Close()

	io.Copy(out, in)
}

func (o *Orchestrator) cleanStaleFillFiles() {
	pattern := filepath.Join(o.runtimeDir, "kldst-fill-*")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return
	}
	o.logger.Infof("cleaning up %d stale fill_disk files from previous run", len(files))
	for _, f := range files {
		os.Remove(f)
	}
}

// Cleanup deletes all stress test resources matching the label selector.
func Cleanup(ctx context.Context, cfg *config.Config) error {
	executor := workload.NewKubectlExecutor(cfg.Namespace, cfg.Workload.KubeconfigContext,
		cfg.Workload.KubectlTimeout, nil)

	selector := cfg.LabelSelector()
	fmt.Printf("Cleaning up resources with selector: %s\n", selector)

	types := []string{"jobs", "deployments", "services", "secrets", "configmaps"}
	for _, rt := range types {
		exitCode, errText := executor.RunRaw(ctx,
			[]string{"delete", rt, "-l", selector,
				"--namespace", cfg.Namespace,
				"--wait=false", "--ignore-not-found"})
		if exitCode == 0 {
			fmt.Printf("  cleaned up %s\n", rt)
		} else {
			fmt.Printf("  failed to clean up %s: %s\n", rt, errText)
		}
	}

	// Also clean stale fill_disk files from runtime dir
	// S1: Use daemon.RuntimeDir() to match the daemon's actual path.
	runtimeDir := daemon.RuntimeDir()
	fillFiles, _ := filepath.Glob(filepath.Join(runtimeDir, "kldst-fill-*"))
	if len(fillFiles) > 0 {
		fmt.Printf("  cleaning %d stale fill_disk files\n", len(fillFiles))
		for _, f := range fillFiles {
			os.Remove(f)
		}
	}

	fmt.Println("Cleanup complete")
	return nil
}
