package report

import (
	"fmt"
	"strings"
)

// DetermineVerdict evaluates all invariants and returns PASS, DEGRADED, or FAIL.
func DetermineVerdict(r *StressTestReport, memoryKillMB int) (string, []string) {
	var issues []string

	// Guard: interrupted run cannot be PASS
	if r.Interrupted {
		issues = append(issues, "INCOMPLETE: test was interrupted before completion")
	}

	// I1: Daemon survives 24h (availability >= 99%)
	if r.DaemonHealth.AvailabilityPct < 99.0 {
		issues = append(issues, fmt.Sprintf("FAIL: daemon availability %.1f%% < 99%% [I1]",
			r.DaemonHealth.AvailabilityPct))
	}

	// I2: No memory leak
	if r.DaemonHealth.MemoryHighWaterMB > int64(memoryKillMB) {
		issues = append(issues, fmt.Sprintf("FAIL: memory %dMB > %dMB [I2]",
			r.DaemonHealth.MemoryHighWaterMB, memoryKillMB))
	}
	if r.DaemonHealth.MemoryGrowthRatio > 5.0 {
		issues = append(issues, fmt.Sprintf("FAIL: memory grew %.1fx from initial [I2]",
			r.DaemonHealth.MemoryGrowthRatio))
	}

	// I3: No token corruption
	if r.TokenIntegrity.CorruptionEvents > 0 {
		issues = append(issues, fmt.Sprintf("FAIL: %d token corruption events [I3]",
			r.TokenIntegrity.CorruptionEvents))
	}

	// I4: Auto-restart works (recovery within 30s)
	if r.ChaosResults.MaxRecoveryTimeMs > 30000 {
		issues = append(issues, fmt.Sprintf("FAIL: max chaos recovery %dms > 30s [I4]",
			r.ChaosResults.MaxRecoveryTimeMs))
	}

	// I5: Concurrent safety (IPC success rate)
	if cat, ok := r.ByCategory["ipc"]; ok && cat.Total > 0 {
		ipcRate := float64(cat.Successes) / float64(cat.Total) * 100
		if ipcRate < 99.0 {
			issues = append(issues, fmt.Sprintf("FAIL: IPC success rate %.1f%% < 99%% [I5]", ipcRate))
		}
	} else {
		issues = append(issues, "DEGRADED: no IPC probes recorded, I5 (concurrent safety) not verified")
	}

	// I6: Persistence survives restart
	if r.TokenIntegrity.PostRestartMismatches > 0 {
		issues = append(issues, fmt.Sprintf("FAIL: %d post-restart token mismatches [I6]",
			r.TokenIntegrity.PostRestartMismatches))
	}

	// I14: p99 latency < 10s (SLO categories only)
	if r.LatencySLO.P99Ms > 10000 {
		issues = append(issues, fmt.Sprintf("FAIL: SLO p99 latency %dms > 10s [I14]",
			r.LatencySLO.P99Ms))
	}

	// SLA violations (direct IPC probes exceeding sla_threshold)
	if r.Summary.SLOInvocations > 0 {
		slaViolationRate := float64(r.Summary.SLAViolations) / float64(r.Summary.SLOInvocations) * 100
		if slaViolationRate > 5.0 {
			issues = append(issues, fmt.Sprintf("DEGRADED: %.1f%% SLA violations (>5%%)", slaViolationRate))
		}
	}

	// I15: Resources cleaned up
	if r.ResourceManagement.OrphansAtEnd > 0 {
		issues = append(issues, fmt.Sprintf("DEGRADED: %d orphaned resources at end [I15]",
			r.ResourceManagement.OrphansAtEnd))
	}

	// Chaos recovery failures
	if r.ChaosResults.RecoveryFailures > 0 {
		issues = append(issues, fmt.Sprintf("FAIL: %d chaos recovery failures",
			r.ChaosResults.RecoveryFailures))
	}

	// SLO success rate (read + mutate + ipc only)
	if r.Summary.SLOSuccessRate < 95.0 {
		issues = append(issues, fmt.Sprintf("FAIL: SLO success rate %.1f%% < 95%%",
			r.Summary.SLOSuccessRate))
	} else if r.Summary.SLOSuccessRate < 99.0 {
		issues = append(issues, fmt.Sprintf("DEGRADED: SLO success rate %.1f%% (95-99%%)",
			r.Summary.SLOSuccessRate))
	}

	// Excessive restarts
	if r.DaemonHealth.RestartCount > 20 {
		issues = append(issues, fmt.Sprintf("DEGRADED: %d daemon restarts (>20)",
			r.DaemonHealth.RestartCount))
	}

	// Token refresh should occur at least once in 24h
	if r.TokenIntegrity.RefreshCount == 0 && !r.Interrupted {
		issues = append(issues, "DEGRADED: no token refresh observed (expected for tokens with >24h expiry)")
	}

	// Determine overall verdict
	if len(issues) == 0 {
		return "PASS", nil
	}
	for _, i := range issues {
		if strings.HasPrefix(i, "FAIL:") || strings.HasPrefix(i, "INCOMPLETE:") {
			return "FAIL", issues
		}
	}
	return "DEGRADED", issues
}
