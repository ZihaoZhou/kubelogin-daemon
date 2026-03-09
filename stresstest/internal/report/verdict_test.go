package report

import (
	"strings"
	"testing"
)

// cleanReport returns a StressTestReport that will produce a PASS verdict.
// Tests mutate individual fields from this baseline to trigger specific verdicts.
func cleanReport() *StressTestReport {
	return &StressTestReport{
		Interrupted: false,
		Summary: SummaryStats{
			TotalInvocations: 10000,
			SLOInvocations:   8000,
			SLOSuccesses:     8000,
			SLOSuccessRate:   100.0,
			SLAViolations:    0,
		},
		ByCategory: map[string]CategoryStats{
			"ipc": {Total: 1000, Successes: 1000, Rate: 100.0},
		},
		LatencySLO: LatencyStats{
			P50Ms: 50,
			P90Ms: 200,
			P95Ms: 500,
			P99Ms: 2000,
			MaxMs: 5000,
		},
		DaemonHealth: DaemonHealthStats{
			TotalPolls:        1000,
			ResponsivePolls:   1000,
			AvailabilityPct:   100.0,
			MemoryHighWaterMB: 80,
			MemoryInitialMB:   20,
			MemoryFinalMB:     30,
			MemoryGrowthRatio: 1.5,
			RestartCount:      0,
		},
		TokenIntegrity: TokenIntegrityStats{
			CorruptionEvents:      0,
			CheckFailures:         0,
			PostRestartMismatches: 0,
			RefreshCount:          5,
		},
		ChaosResults: ChaosResultStats{
			TotalInjections:   10,
			MaxRecoveryTimeMs: 5000,
			RecoveryFailures:  0,
		},
		ResourceManagement: ResourceMgmtStats{
			Created:      100,
			Reaped:       100,
			OrphansAtEnd: 0,
		},
	}
}

const defaultMemoryKillMB = 500

func TestDetermineVerdict_Pass(t *testing.T) {
	r := cleanReport()
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "PASS" {
		t.Fatalf("expected PASS, got %s; issues: %v", verdict, issues)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got: %v", issues)
	}
}

func TestDetermineVerdict_Interrupted(t *testing.T) {
	r := cleanReport()
	r.Interrupted = true
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for interrupted run, got %s", verdict)
	}
	found := false
	for _, iss := range issues {
		if strings.Contains(iss, "INCOMPLETE") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected INCOMPLETE issue, got: %v", issues)
	}
}

func TestDetermineVerdict_I1_LowAvailability(t *testing.T) {
	r := cleanReport()
	r.DaemonHealth.AvailabilityPct = 98.5
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for low availability, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I1]")
}

func TestDetermineVerdict_I2_MemoryHighWater(t *testing.T) {
	r := cleanReport()
	r.DaemonHealth.MemoryHighWaterMB = 600
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for memory high water, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I2]")
}

func TestDetermineVerdict_I2_MemoryGrowthRatio(t *testing.T) {
	r := cleanReport()
	r.DaemonHealth.MemoryGrowthRatio = 6.0
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for memory growth, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I2]")
}

func TestDetermineVerdict_I2_MemoryAtExactLimit(t *testing.T) {
	r := cleanReport()
	// At exactly the limit should not fail (> check, not >=).
	r.DaemonHealth.MemoryHighWaterMB = int64(defaultMemoryKillMB)
	r.DaemonHealth.MemoryGrowthRatio = 5.0
	verdict, _ := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "PASS" {
		t.Fatalf("expected PASS at exact memory limit, got %s", verdict)
	}
}

func TestDetermineVerdict_I3_TokenCorruption(t *testing.T) {
	r := cleanReport()
	r.TokenIntegrity.CorruptionEvents = 1
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for token corruption, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I3]")
}

func TestDetermineVerdict_I4_SlowChaosRecovery(t *testing.T) {
	r := cleanReport()
	r.ChaosResults.MaxRecoveryTimeMs = 31000
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for slow chaos recovery, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I4]")
}

func TestDetermineVerdict_I4_ExactlyAt30s(t *testing.T) {
	r := cleanReport()
	// At exactly 30000ms should not fail (> check, not >=).
	r.ChaosResults.MaxRecoveryTimeMs = 30000
	verdict, _ := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "PASS" {
		t.Fatalf("expected PASS at exactly 30s recovery, got %s", verdict)
	}
}

func TestDetermineVerdict_I5_LowIPCRate(t *testing.T) {
	r := cleanReport()
	r.ByCategory["ipc"] = CategoryStats{Total: 1000, Successes: 980, Rate: 98.0}
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for low IPC rate, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I5]")
}

func TestDetermineVerdict_I5_NoIPCProbes(t *testing.T) {
	r := cleanReport()
	delete(r.ByCategory, "ipc")
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "DEGRADED" {
		t.Fatalf("expected DEGRADED when no IPC probes, got %s", verdict)
	}
	assertIssueContains(t, issues, "I5")
}

func TestDetermineVerdict_I5_ZeroTotalIPC(t *testing.T) {
	r := cleanReport()
	r.ByCategory["ipc"] = CategoryStats{Total: 0, Successes: 0}
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	// Zero total IPC goes through the else branch -> DEGRADED
	if verdict != "DEGRADED" {
		t.Fatalf("expected DEGRADED for zero total IPC, got %s", verdict)
	}
	assertIssueContains(t, issues, "I5")
}

func TestDetermineVerdict_I6_PostRestartMismatch(t *testing.T) {
	r := cleanReport()
	r.TokenIntegrity.PostRestartMismatches = 2
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for post-restart mismatches, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I6]")
}

func TestDetermineVerdict_I14_HighP99Latency(t *testing.T) {
	r := cleanReport()
	r.LatencySLO.P99Ms = 11000
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for high p99 latency, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I14]")
}

func TestDetermineVerdict_I14_ExactlyAt10s(t *testing.T) {
	r := cleanReport()
	// At exactly 10000ms should not fail (> check, not >=).
	r.LatencySLO.P99Ms = 10000
	verdict, _ := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "PASS" {
		t.Fatalf("expected PASS at exactly 10s p99 latency, got %s", verdict)
	}
}

func TestDetermineVerdict_SLAViolationRate(t *testing.T) {
	tests := []struct {
		name           string
		sloInvocations int64
		slaViolations  int64
		wantVerdict    string
		wantContains   string
	}{
		{
			name:           "below 5% threshold",
			sloInvocations: 1000,
			slaViolations:  49,
			wantVerdict:    "PASS",
		},
		{
			name:           "above 5% threshold",
			sloInvocations: 1000,
			slaViolations:  60,
			wantVerdict:    "DEGRADED",
			wantContains:   "SLA violations",
		},
		{
			name:           "zero invocations skips check",
			sloInvocations: 0,
			slaViolations:  0,
			wantVerdict:    "PASS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cleanReport()
			r.Summary.SLOInvocations = tt.sloInvocations
			r.Summary.SLAViolations = tt.slaViolations
			verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
			if verdict != tt.wantVerdict {
				t.Fatalf("expected %s, got %s; issues: %v", tt.wantVerdict, verdict, issues)
			}
			if tt.wantContains != "" {
				assertIssueContains(t, issues, tt.wantContains)
			}
		})
	}
}

func TestDetermineVerdict_I15_OrphanResources(t *testing.T) {
	r := cleanReport()
	r.ResourceManagement.OrphansAtEnd = 3
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "DEGRADED" {
		t.Fatalf("expected DEGRADED for orphan resources, got %s", verdict)
	}
	assertIssueContains(t, issues, "[I15]")
}

func TestDetermineVerdict_ChaosRecoveryFailures(t *testing.T) {
	r := cleanReport()
	r.ChaosResults.RecoveryFailures = 1
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL for chaos recovery failures, got %s", verdict)
	}
	assertIssueContains(t, issues, "chaos recovery failures")
}

func TestDetermineVerdict_SLOSuccessRate(t *testing.T) {
	tests := []struct {
		name        string
		rate        float64
		wantVerdict string
	}{
		{name: "100%", rate: 100.0, wantVerdict: "PASS"},
		{name: "99%", rate: 99.0, wantVerdict: "PASS"},
		{name: "98.5%", rate: 98.5, wantVerdict: "DEGRADED"},
		{name: "95%", rate: 95.0, wantVerdict: "DEGRADED"},
		{name: "94.9%", rate: 94.9, wantVerdict: "FAIL"},
		{name: "0%", rate: 0.0, wantVerdict: "FAIL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cleanReport()
			r.Summary.SLOSuccessRate = tt.rate
			verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
			if verdict != tt.wantVerdict {
				t.Fatalf("expected %s for SLO rate %.1f%%, got %s; issues: %v",
					tt.wantVerdict, tt.rate, verdict, issues)
			}
		})
	}
}

func TestDetermineVerdict_ExcessiveRestarts(t *testing.T) {
	tests := []struct {
		name        string
		count       int64
		wantVerdict string
	}{
		{name: "20 restarts ok", count: 20, wantVerdict: "PASS"},
		{name: "21 restarts degraded", count: 21, wantVerdict: "DEGRADED"},
		{name: "100 restarts degraded", count: 100, wantVerdict: "DEGRADED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := cleanReport()
			r.DaemonHealth.RestartCount = tt.count
			verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
			if verdict != tt.wantVerdict {
				t.Fatalf("expected %s for %d restarts, got %s; issues: %v",
					tt.wantVerdict, tt.count, verdict, issues)
			}
		})
	}
}

func TestDetermineVerdict_NoTokenRefresh(t *testing.T) {
	r := cleanReport()
	r.TokenIntegrity.RefreshCount = 0
	r.Interrupted = false
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "DEGRADED" {
		t.Fatalf("expected DEGRADED for no token refresh, got %s", verdict)
	}
	assertIssueContains(t, issues, "no token refresh observed")
}

func TestDetermineVerdict_NoTokenRefresh_InterruptedSkips(t *testing.T) {
	// When interrupted and no refresh, the INCOMPLETE issue already makes it FAIL,
	// but the "no token refresh" check should be skipped (guarded by !r.Interrupted).
	r := cleanReport()
	r.TokenIntegrity.RefreshCount = 0
	r.Interrupted = true
	_, issues := DetermineVerdict(r, defaultMemoryKillMB)
	for _, iss := range issues {
		if strings.Contains(iss, "no token refresh") {
			t.Fatal("should not report 'no token refresh' when interrupted")
		}
	}
}

func TestDetermineVerdict_MultipleDegradedIssues(t *testing.T) {
	r := cleanReport()
	// DEGRADED: orphans + excessive restarts + no token refresh
	r.ResourceManagement.OrphansAtEnd = 5
	r.DaemonHealth.RestartCount = 25
	r.TokenIntegrity.RefreshCount = 0
	verdict, issues := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "DEGRADED" {
		t.Fatalf("expected DEGRADED with multiple degraded issues, got %s", verdict)
	}
	if len(issues) < 3 {
		t.Fatalf("expected at least 3 issues, got %d: %v", len(issues), issues)
	}
}

func TestDetermineVerdict_FailOverridesDegraded(t *testing.T) {
	r := cleanReport()
	// One DEGRADED (orphans) + one FAIL (token corruption)
	r.ResourceManagement.OrphansAtEnd = 5
	r.TokenIntegrity.CorruptionEvents = 1
	verdict, _ := DetermineVerdict(r, defaultMemoryKillMB)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL when both FAIL and DEGRADED issues present, got %s", verdict)
	}
}

func TestDetermineVerdict_CustomMemoryKillMB(t *testing.T) {
	r := cleanReport()
	r.DaemonHealth.MemoryHighWaterMB = 250
	// With memoryKillMB=200, 250 > 200 -> FAIL
	verdict, _ := DetermineVerdict(r, 200)
	if verdict != "FAIL" {
		t.Fatalf("expected FAIL with custom memoryKillMB=200, got %s", verdict)
	}
	// With memoryKillMB=300, 250 < 300 -> PASS
	verdict, _ = DetermineVerdict(r, 300)
	if verdict != "PASS" {
		t.Fatalf("expected PASS with custom memoryKillMB=300, got %s", verdict)
	}
}

// assertIssueContains is a helper that checks if at least one issue contains the substring.
func assertIssueContains(t *testing.T, issues []string, substr string) {
	t.Helper()
	for _, iss := range issues {
		if strings.Contains(iss, substr) {
			return
		}
	}
	t.Fatalf("expected at least one issue containing %q, got: %v", substr, issues)
}
