package report

import "time"

// StressTestReport is the top-level report structure.
type StressTestReport struct {
	TestRunID        string    `json:"test_run_id"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	Duration         string    `json:"duration"`
	Platform         string    `json:"platform"`
	Namespace        string    `json:"namespace"`
	RNGSeed          int64     `json:"rng_seed"`
	DaemonBinaryHash string    `json:"daemon_binary_hash"`
	Interrupted      bool      `json:"interrupted"`

	Summary SummaryStats `json:"summary"`

	ByCategory map[string]CategoryStats `json:"by_category"`

	LatencySLO LatencyStats `json:"latency_slo"`

	DaemonHealth DaemonHealthStats `json:"daemon_health"`

	TokenIntegrity TokenIntegrityStats `json:"token_integrity"`

	ChaosResults ChaosResultStats `json:"chaos_results"`

	ResourceManagement ResourceMgmtStats `json:"resource_management"`

	Timeline []TimelineEvent `json:"timeline,omitempty"`

	Verdict string   `json:"verdict"`
	Issues  []string `json:"issues,omitempty"`
}

// SummaryStats holds top-level counters.
type SummaryStats struct {
	TotalInvocations int64   `json:"total_invocations"`
	SLOInvocations   int64   `json:"slo_invocations"`
	SLOSuccesses     int64   `json:"slo_successes"`
	SLOSuccessRate   float64 `json:"slo_success_rate"`
	SLAViolations    int64   `json:"sla_violations"`
	DaemonRestarts   int64   `json:"daemon_restarts"`
}

// CategoryStats holds per-category metrics.
type CategoryStats struct {
	Total     int64   `json:"total"`
	Successes int64   `json:"successes"`
	Rate      float64 `json:"rate"`
}

// LatencyStats holds percentile latency data.
type LatencyStats struct {
	P50Ms int64 `json:"p50_ms"`
	P90Ms int64 `json:"p90_ms"`
	P95Ms int64 `json:"p95_ms"`
	P99Ms int64 `json:"p99_ms"`
	MaxMs int64 `json:"max_ms"`
}

// DaemonHealthStats holds daemon health metrics.
type DaemonHealthStats struct {
	TotalPolls        int64   `json:"total_polls"`
	ResponsivePolls   int64   `json:"responsive_polls"`
	AvailabilityPct   float64 `json:"availability_pct"`
	MemoryHighWaterMB int64   `json:"memory_high_water_mb"`
	MemoryInitialMB   int64   `json:"memory_initial_mb"`
	MemoryFinalMB     int64   `json:"memory_final_mb"`
	MemoryGrowthRatio float64 `json:"memory_growth_ratio"`
	RestartCount      int64   `json:"restart_count"`
	LongestOutageMs   int64   `json:"longest_outage_ms"`
}

// TokenIntegrityStats holds token validation metrics.
type TokenIntegrityStats struct {
	CorruptionEvents      int `json:"corruption_events"`
	CheckFailures         int `json:"check_failures"`
	PostRestartMismatches int `json:"post_restart_mismatches"`
	RefreshCount          int `json:"refresh_count"`
}

// ChaosResultStats holds chaos injection metrics.
type ChaosResultStats struct {
	TotalInjections    int64                    `json:"total_injections"`
	ByType             map[string]int64         `json:"by_type"`
	RecoveryTimeByType map[string]LatencyStats  `json:"recovery_time_by_type"`
	RecoveryFailures   int64                    `json:"recovery_failures"`
	MaxRecoveryTimeMs  int64                    `json:"max_recovery_time_ms"`
}

// ResourceMgmtStats holds resource management metrics.
type ResourceMgmtStats struct {
	Created      int64 `json:"created"`
	Reaped       int64 `json:"reaped"`
	OrphansAtEnd int64 `json:"orphans_at_end"`
}

// TimelineEvent is a significant event during the test.
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
}
