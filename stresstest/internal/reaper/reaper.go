package reaper

import (
	"context"
	"fmt"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/config"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/workload"
)

// Reaper periodically cleans up Kubernetes resources created by the stress test.
type Reaper struct {
	cfg       config.ReaperConfig
	namespace string
	selector  string
	logger    *logging.Logger
	recorder  *metrics.Recorder
	executor  *workload.KubectlExecutor
	tracker   *workload.ResourceTracker
}

// New creates a new reaper.
func New(
	cfg config.ReaperConfig,
	namespace, selector string,
	logger *logging.Logger,
	recorder *metrics.Recorder,
	executor *workload.KubectlExecutor,
	tracker *workload.ResourceTracker,
) *Reaper {
	return &Reaper{
		cfg:       cfg,
		namespace: namespace,
		selector:  selector,
		logger:    logger,
		recorder:  recorder,
		executor:  executor,
		tracker:   tracker,
	}
}

// Run starts the periodic reaper loop.
func (r *Reaper) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.sweep(ctx)
		case <-ctx.Done():
			r.FinalCleanup(context.Background())
			return nil
		}
	}
}

var resourceTypes = []string{"jobs", "deployments", "services", "secrets", "configmaps"}

func (r *Reaper) sweep(ctx context.Context) {
	// Use tracker to find old resources first
	old := r.tracker.ListOlderThan(r.cfg.MaxAge)
	if len(old) == 0 {
		return
	}

	r.logger.Infof("reaper: sweeping %d resources older than %s", len(old), r.cfg.MaxAge)

	for _, res := range old {
		exitCode, errText := r.executor.RunRaw(ctx,
			[]string{"delete", res.Kind, res.Name,
				"--namespace", r.namespace,
				"--wait=false", "--ignore-not-found"})

		success := exitCode == 0
		var ageS int64
		if !res.CreatedAt.IsZero() {
			ageS = int64(time.Since(res.CreatedAt).Seconds())
		}

		r.recorder.RecordReaper(res.Kind, res.Name, ageS, success, errText)

		if success {
			r.tracker.Remove(res.Kind, res.Name)
		} else {
			r.logger.Warnf("reaper: failed to delete %s/%s: %s", res.Kind, res.Name, errText)
		}
	}
}

// FinalCleanup does a bulk delete of all stress test resources.
func (r *Reaper) FinalCleanup(ctx context.Context) {
	r.logger.Info("reaper: running final cleanup")

	// Delete in reverse dependency order
	for _, rt := range resourceTypes {
		for attempt := 0; attempt < 3; attempt++ {
			exitCode, errText := r.executor.RunRaw(ctx,
				[]string{"delete", rt, "-l", r.selector,
					"--namespace", r.namespace,
					"--wait=false", "--ignore-not-found"})
			if exitCode == 0 {
				r.logger.Infof("reaper: cleaned up %s", rt)
				break
			}
			r.logger.Warnf("reaper: cleanup %s attempt %d failed: %s", rt, attempt+1, errText)
			time.Sleep(2 * time.Second)
		}
	}

	remaining := r.tracker.OrphansAtEnd()
	if remaining > 0 {
		r.logger.Warnf("reaper: %d tracked resources remain after final cleanup", remaining)
		r.recorder.RecordTimeline("reaper",
			fmt.Sprintf("final cleanup: %d orphans remaining", remaining))
	} else {
		r.logger.Info("reaper: final cleanup complete, zero orphans")
	}
}
