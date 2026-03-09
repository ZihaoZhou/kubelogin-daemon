package workload

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
)

// Generator implements the 3-phase burst pattern workload.
type Generator struct {
	cfg     config.WorkloadConfig
	rng     *rand.Rand
	logger  *logging.Logger

	executor    *KubectlExecutor
	prober      *DirectSocketProber
	tracker     *ResourceTracker
	recorder    *metrics.Recorder
	rateLimiter *rate.Limiter
	managedBy   string

	phase       atomic.Int32
	phaseChange func(Phase) // callback to notify health monitor

	totalInvocations atomic.Int64
	totalSuccesses   atomic.Int64
	totalFailures    atomic.Int64
	slaViolations    atomic.Int64

	// S3: Track consecutive daemon errors (needs-auth) for double-fault detection.
	consecutiveDaemonErrors atomic.Int64
	doubleFaultLogged       atomic.Bool
}

// NewGenerator creates a new workload generator.
func NewGenerator(
	cfg config.WorkloadConfig,
	rng *rand.Rand,
	logger *logging.Logger,
	executor *KubectlExecutor,
	prober *DirectSocketProber,
	tracker *ResourceTracker,
	recorder *metrics.Recorder,
	managedBy string,
) *Generator {
	g := &Generator{
		cfg:         cfg,
		rng:         rng,
		logger:      logger,
		executor:    executor,
		prober:      prober,
		tracker:     tracker,
		recorder:    recorder,
		rateLimiter: rate.NewLimiter(rate.Limit(cfg.RateLimit.SteadyQPS), cfg.RateLimit.SteadyBurst),
		managedBy:   managedBy,
	}
	return g
}

// SetPhaseCallback registers a callback for phase changes.
func (g *Generator) SetPhaseCallback(fn func(Phase)) {
	g.phaseChange = fn
}

// CurrentPhase returns the current workload phase.
func (g *Generator) CurrentPhase() Phase {
	return Phase(g.phase.Load())
}

// Stats returns current counters.
func (g *Generator) Stats() (total, successes, failures, slaViol int64) {
	return g.totalInvocations.Load(), g.totalSuccesses.Load(),
		g.totalFailures.Load(), g.slaViolations.Load()
}

// Run executes the workload generation loop until ctx is cancelled.
func (g *Generator) Run(ctx context.Context) error {
	for {
		phase := g.pickPhase()
		phaseDur := g.randomDuration(g.cfg.PhaseDurationMin, g.cfg.PhaseDurationMax)
		phaseEnd := time.Now().Add(phaseDur)

		g.phase.Store(int32(phase))
		g.logger.Infof("entering %s phase for %s", phase, phaseDur)

		if g.phaseChange != nil {
			g.phaseChange(phase)
		}

		// Switch rate limiter to phase-appropriate QPS
		switch phase {
		case PhaseSteady:
			g.rateLimiter.SetLimit(rate.Limit(g.cfg.RateLimit.SteadyQPS))
			g.rateLimiter.SetBurst(g.cfg.RateLimit.SteadyBurst)
		case PhaseBurst:
			g.rateLimiter.SetLimit(rate.Limit(g.cfg.RateLimit.BurstQPS))
			g.rateLimiter.SetBurst(g.cfg.RateLimit.BurstBurst)
		case PhaseQuiescent:
			g.rateLimiter.SetLimit(rate.Limit(g.cfg.RateLimit.QuietQPS))
			g.rateLimiter.SetBurst(g.cfg.RateLimit.QuietBurst)
		}

		for time.Now().Before(phaseEnd) {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			minConc, maxConc, minDelay, maxDelay := g.phaseParams(phase)
			concurrency := g.randomInt(minConc, maxConc)
			delay := g.randomDuration(minDelay, maxDelay)

			if concurrency > 0 {
				var wg sync.WaitGroup
				for i := 0; i < concurrency; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if err := g.rateLimiter.Wait(ctx); err != nil {
							return
						}
						g.executeOneCommand(ctx)
					}()
				}
				wg.Wait()
			}

			// S3: Auto-stop on unrecoverable double-fault.
			if g.doubleFaultLogged.Load() {
				return fmt.Errorf("S3: unrecoverable double-fault detected (%d consecutive daemon errors), stopping workload",
					g.consecutiveDaemonErrors.Load())
			}

			// Direct IPC probes — skip during quiescent (would reset idle timer)
			if phase != PhaseQuiescent && g.cfg.DirectIPCRate > 0 && g.prober != nil {
				g.prober.RunProbes(g.cfg.DirectIPCRate)
			}

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (g *Generator) executeOneCommand(ctx context.Context) {
	cat := g.selectCategory()
	var tmpl CmdTemplate
	var commandType string
	var slotReserved bool
	var resourceName string

	switch cat {
	case CatReadOnly:
		tmpl, commandType = g.selectWeightedTemplate(readOnlyTemplates)
		tmpl = g.expandPlaceholders(tmpl)
	case CatMutating:
		tmpl, commandType, slotReserved, resourceName = g.generateMutateCommand()
	case CatInvalid:
		tmpl, commandType = g.selectWeightedTemplate(invalidTemplates)
		tmpl = g.expandPlaceholders(tmpl)
	case CatFuzzing:
		tmpl = CmdTemplate{Args: g.generateFuzzArgs()}
		commandType = "fuzz_" + tmpl.Args[0]
	default:
		return
	}

	// Safety: if a slot was reserved, ensure it's committed or released
	if slotReserved {
		defer func() {
			// If we reach here without commit, release the slot
		}()
	}

	result := g.executor.Run(ctx, tmpl, cat, commandType)
	result.ResourceName = resourceName

	g.totalInvocations.Add(1)
	if result.FailureClass == FailNone {
		g.totalSuccesses.Add(1)
		g.consecutiveDaemonErrors.Store(0)
		if slotReserved && resourceName != "" {
			kind := extractKind(tmpl.Args)
			g.tracker.CommitSlot(kind, resourceName)
			slotReserved = false // committed, don't release
		}
	} else {
		g.totalFailures.Add(1)
		// S3: Track consecutive daemon errors for double-fault detection.
		// A sustained run of FailDaemonError (needs-auth) means the daemon is
		// alive but can't serve tokens — likely a corrupt+kill double-fault.
		if result.FailureClass == FailDaemonError {
			n := g.consecutiveDaemonErrors.Add(1)
			if n >= 20 && g.doubleFaultLogged.CompareAndSwap(false, true) {
				g.logger.Warnf("S3: %d consecutive daemon errors — possible double-fault "+
					"(token corruption + daemon kill overlap). Daemon is running but cannot serve tokens. "+
					"Manual 'kubelogin-daemon login' may be required to recover.", n)
				g.recorder.RecordTimeline("double_fault",
					fmt.Sprintf("%d consecutive daemon errors (needs-auth)", n))
			}
		} else {
			g.consecutiveDaemonErrors.Store(0)
		}
	}

	// Release unredeemed slot
	if slotReserved {
		g.tracker.ReleaseSlot()
	}

	g.recorder.RecordResult(
		result.Timestamp,
		string(result.Category),
		result.CommandType,
		result.Args,
		result.ExitCode,
		result.Duration,
		string(result.FailureClass),
		result.Error,
		result.ResourceName,
		result.SLAViolation,
		result.ExpectClientError,
	)
}

func (g *Generator) selectCategory() CommandCategory {
	r := g.rng.Intn(100)
	w := g.cfg.CommandWeights
	if r < w.Read {
		return CatReadOnly
	}
	r -= w.Read
	if r < w.Mutate {
		return CatMutating
	}
	r -= w.Mutate
	if r < w.Invalid {
		return CatInvalid
	}
	return CatFuzzing
}

func (g *Generator) selectWeightedTemplate(templates []CmdTemplate) (CmdTemplate, string) {
	totalWeight := 0
	for _, t := range templates {
		totalWeight += t.Weight
	}
	r := g.rng.Intn(totalWeight)
	for _, t := range templates {
		r -= t.Weight
		if r < 0 {
			name := strings.Join(t.Args[:min(2, len(t.Args))], "_")
			return t, name
		}
	}
	return templates[0], strings.Join(templates[0].Args[:min(2, len(templates[0].Args))], "_")
}

func (g *Generator) generateMutateCommand() (tmpl CmdTemplate, commandType string, slotReserved bool, resourceName string) {
	if !g.tracker.ReserveSlot() {
		// At capacity — do a read instead
		t, name := g.selectWeightedTemplate(readOnlyTemplates)
		t = g.expandPlaceholders(t)
		return t, name, false, ""
	}
	slotReserved = true

	epochHex := fmt.Sprintf("%x", time.Now().Unix())
	randHex := randomHex8(g.rng)

	mutateTypes := []struct {
		code   string
		kind   string
		weight int
	}{
		{"c", "configmap", 30},
		{"s", "secret", 20},
		{"j", "job", 15},
	}

	// Weighted selection
	totalWeight := 0
	for _, m := range mutateTypes {
		totalWeight += m.weight
	}
	r := g.rng.Intn(totalWeight)
	var selected struct {
		code string
		kind string
	}
	for _, m := range mutateTypes {
		r -= m.weight
		if r < 0 {
			selected.code = m.code
			selected.kind = m.kind
			break
		}
	}

	resourceName = fmt.Sprintf("kldst-%s-%s-%s", selected.code, epochHex, randHex)

	switch selected.kind {
	case "configmap":
		tmpl = CmdTemplate{
			Args: []string{"create", "configmap", resourceName,
				"--from-literal=stress=test",
				"-l", "app.kubernetes.io/managed-by=" + g.managedBy},
		}
	case "secret":
		tmpl = CmdTemplate{
			Args: []string{"create", "secret", "generic", resourceName,
				"--from-literal=stress=test",
				"-l", "app.kubernetes.io/managed-by=" + g.managedBy},
		}
	case "job":
		// Use apply -f - for jobs since they need a spec
		jobYAML := fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  labels:
    app.kubernetes.io/managed-by: %s
spec:
  ttlSecondsAfterFinished: 60
  template:
    spec:
      containers:
      - name: stress
        image: busybox
        command: ["echo", "stress-test"]
      restartPolicy: Never
  backoffLimit: 0`, resourceName, g.managedBy)
		tmpl = CmdTemplate{
			Args:  []string{"apply", "-f", "-"},
			Stdin: jobYAML,
		}
	}

	commandType = "create_" + selected.kind
	return
}

func (g *Generator) generateFuzzArgs() []string {
	verb := fuzzVerbs[g.rng.Intn(len(fuzzVerbs))]
	resource := fuzzResources[g.rng.Intn(len(fuzzResources))]
	args := []string{verb, resource}

	if g.rng.Float64() < 0.5 {
		args = append(args, "stress-"+randomHex8(g.rng))
	}
	if g.rng.Float64() < 0.3 {
		nFlags := g.rng.Intn(3) + 1
		for i := 0; i < nFlags; i++ {
			args = append(args, fuzzFlags[g.rng.Intn(len(fuzzFlags))])
		}
	}
	return args
}

func (g *Generator) expandPlaceholders(tmpl CmdTemplate) CmdTemplate {
	expanded := CmdTemplate{
		Weight:            tmpl.Weight,
		Stdin:             tmpl.Stdin,
		ExpectClientError: tmpl.ExpectClientError,
	}
	expanded.Args = make([]string, len(tmpl.Args))
	for i, a := range tmpl.Args {
		switch a {
		case "{existing-pod}":
			pods := g.tracker.ListByKind("pod")
			if len(pods) > 0 {
				expanded.Args[i] = pods[g.rng.Intn(len(pods))]
			} else {
				expanded.Args[i] = "nonexistent-pod"
				expanded.ExpectClientError = true
			}
		case "{existing-svc}":
			svcs := g.tracker.ListByKind("service")
			if len(svcs) > 0 {
				expanded.Args[i] = svcs[g.rng.Intn(len(svcs))]
			} else {
				expanded.Args[i] = "nonexistent-svc"
				expanded.ExpectClientError = true
			}
		case "{random}":
			expanded.Args[i] = randomHex8(g.rng)
		default:
			if strings.Contains(a, "{random}") {
				expanded.Args[i] = strings.ReplaceAll(a, "{random}", randomHex8(g.rng))
			} else {
				expanded.Args[i] = a
			}
		}
	}
	return expanded
}

func (g *Generator) pickPhase() Phase {
	r := g.rng.Intn(100)
	if r < g.cfg.SteadyWeight {
		return PhaseSteady
	}
	r -= g.cfg.SteadyWeight
	if r < g.cfg.BurstWeight {
		return PhaseBurst
	}
	return PhaseQuiescent
}

func (g *Generator) phaseParams(phase Phase) (minConc, maxConc int, minDelay, maxDelay time.Duration) {
	switch phase {
	case PhaseSteady:
		return g.cfg.SteadyMinConc, g.cfg.SteadyMaxConc, g.cfg.SteadyMinDelay, g.cfg.SteadyMaxDelay
	case PhaseBurst:
		return g.cfg.BurstMinConc, g.cfg.BurstMaxConc, g.cfg.BurstMinDelay, g.cfg.BurstMaxDelay
	case PhaseQuiescent:
		return g.cfg.QuietMinConc, g.cfg.QuietMaxConc, g.cfg.QuietMinDelay, g.cfg.QuietMaxDelay
	}
	return 1, 1, time.Second, time.Second
}

func (g *Generator) randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}
	delta := max - min
	return min + time.Duration(g.rng.Int63n(int64(delta)))
}

func (g *Generator) randomInt(min, max int) int {
	if min >= max {
		return min
	}
	return min + g.rng.Intn(max-min+1)
}

func randomHex8(rng *rand.Rand) string {
	return fmt.Sprintf("%08x", rng.Uint32())
}

func extractKind(args []string) string {
	if len(args) >= 2 {
		switch args[0] {
		case "create":
			return args[1]
		case "apply":
			return "apply"
		}
	}
	return "unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
