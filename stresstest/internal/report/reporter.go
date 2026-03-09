package report

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/metrics"
)

// Reporter generates reports from the SQLite metrics DB.
type Reporter struct {
	db          *sql.DB
	testRunID   string
	percentiles []int
}

// NewReporter creates a new reporter.
func NewReporter(db *sql.DB, testRunID string, percentiles []int) *Reporter {
	return &Reporter{
		db:          db,
		testRunID:   testRunID,
		percentiles: percentiles,
	}
}

// Generate creates a report from the DB.
func (r *Reporter) Generate() *StressTestReport {
	rpt := &StressTestReport{
		TestRunID: r.testRunID,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}

	r.fillSummary(rpt)
	r.fillByCategory(rpt)
	r.fillLatency(rpt)
	r.fillDaemonHealth(rpt)
	r.fillChaosResults(rpt)
	r.fillResourceManagement(rpt)
	r.fillTimeline(rpt)

	return rpt
}

// Write writes the report to a JSON file.
func (r *Reporter) Write(rpt *StressTestReport, outputDir string) error {
	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	path := filepath.Join(outputDir, "report.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	return nil
}

func (r *Reporter) fillSummary(rpt *StressTestReport) {
	// Total invocations
	r.db.QueryRow(`SELECT COUNT(*) FROM command_results WHERE test_run_id = ?`,
		r.testRunID).Scan(&rpt.Summary.TotalInvocations)

	// SLO invocations (read + mutate + ipc, excluding ExpectClientError)
	r.db.QueryRow(`SELECT COUNT(*) FROM command_results
		WHERE test_run_id = ? AND category IN ('read', 'mutate', 'ipc')
		AND expect_client_error = 0`,
		r.testRunID).Scan(&rpt.Summary.SLOInvocations)

	// SLO successes
	r.db.QueryRow(`SELECT COUNT(*) FROM command_results
		WHERE test_run_id = ? AND category IN ('read', 'mutate', 'ipc')
		AND expect_client_error = 0 AND failure_class = ''`,
		r.testRunID).Scan(&rpt.Summary.SLOSuccesses)

	if rpt.Summary.SLOInvocations > 0 {
		rpt.Summary.SLOSuccessRate = float64(rpt.Summary.SLOSuccesses) / float64(rpt.Summary.SLOInvocations) * 100
	}

	// SLA violations
	r.db.QueryRow(`SELECT COUNT(*) FROM command_results
		WHERE test_run_id = ? AND sla_violation = 1`,
		r.testRunID).Scan(&rpt.Summary.SLAViolations)
}

func (r *Reporter) fillByCategory(rpt *StressTestReport) {
	rpt.ByCategory = make(map[string]CategoryStats)

	rows, err := r.db.Query(`SELECT category, COUNT(*),
		SUM(CASE WHEN failure_class = '' THEN 1 ELSE 0 END)
		FROM command_results WHERE test_run_id = ?
		GROUP BY category`, r.testRunID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var cat string
		var stats CategoryStats
		if err := rows.Scan(&cat, &stats.Total, &stats.Successes); err != nil {
			continue
		}
		if stats.Total > 0 {
			stats.Rate = float64(stats.Successes) / float64(stats.Total) * 100
		}
		rpt.ByCategory[cat] = stats
	}
}

func (r *Reporter) fillLatency(rpt *StressTestReport) {
	// Get all SLO latencies for percentile computation
	rows, err := r.db.Query(`SELECT duration_ms FROM command_results
		WHERE test_run_id = ? AND category IN ('read', 'mutate', 'ipc')
		AND expect_client_error = 0
		ORDER BY duration_ms`, r.testRunID)
	if err != nil {
		return
	}
	defer rows.Close()

	var latencies []int64
	for rows.Next() {
		var ms int64
		if err := rows.Scan(&ms); err != nil {
			continue
		}
		latencies = append(latencies, ms)
	}

	if len(latencies) == 0 {
		return
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	rpt.LatencySLO.P50Ms = percentile(latencies, 50)
	rpt.LatencySLO.P90Ms = percentile(latencies, 90)
	rpt.LatencySLO.P95Ms = percentile(latencies, 95)
	rpt.LatencySLO.P99Ms = percentile(latencies, 99)
	rpt.LatencySLO.MaxMs = latencies[len(latencies)-1]
}

func (r *Reporter) fillDaemonHealth(rpt *StressTestReport) {
	// Total and responsive polls
	r.db.QueryRow(`SELECT COUNT(*), SUM(responsive) FROM health_snapshots
		WHERE test_run_id = ?`, r.testRunID).Scan(
		&rpt.DaemonHealth.TotalPolls, &rpt.DaemonHealth.ResponsivePolls)

	if rpt.DaemonHealth.TotalPolls > 0 {
		rpt.DaemonHealth.AvailabilityPct = float64(rpt.DaemonHealth.ResponsivePolls) /
			float64(rpt.DaemonHealth.TotalPolls) * 100
	}

	// Memory high water mark
	var maxRSS sql.NullInt64
	r.db.QueryRow(`SELECT MAX(memory_rss) FROM health_snapshots
		WHERE test_run_id = ? AND memory_rss > 0`, r.testRunID).Scan(&maxRSS)
	if maxRSS.Valid {
		rpt.DaemonHealth.MemoryHighWaterMB = maxRSS.Int64 / (1024 * 1024)
	}

	// Initial and final memory
	var initialRSS, finalRSS sql.NullInt64
	r.db.QueryRow(`SELECT memory_rss FROM health_snapshots
		WHERE test_run_id = ? AND memory_rss > 0
		ORDER BY timestamp ASC LIMIT 1`, r.testRunID).Scan(&initialRSS)
	r.db.QueryRow(`SELECT memory_rss FROM health_snapshots
		WHERE test_run_id = ? AND memory_rss > 0
		ORDER BY timestamp DESC LIMIT 1`, r.testRunID).Scan(&finalRSS)

	if initialRSS.Valid {
		rpt.DaemonHealth.MemoryInitialMB = initialRSS.Int64 / (1024 * 1024)
	}
	if finalRSS.Valid {
		rpt.DaemonHealth.MemoryFinalMB = finalRSS.Int64 / (1024 * 1024)
	}
	if initialRSS.Valid && initialRSS.Int64 > 0 && finalRSS.Valid {
		rpt.DaemonHealth.MemoryGrowthRatio = float64(finalRSS.Int64) / float64(initialRSS.Int64)
	}

	// Restart count
	r.db.QueryRow(`SELECT COUNT(*) FROM timeline_events
		WHERE test_run_id = ? AND category = 'restart'`, r.testRunID).Scan(
		&rpt.DaemonHealth.RestartCount)

	// Longest outage (consecutive non-responsive polls)
	rpt.DaemonHealth.LongestOutageMs = r.computeLongestOutage()
}

func (r *Reporter) computeLongestOutage() int64 {
	rows, err := r.db.Query(`SELECT responsive, response_time_ms FROM health_snapshots
		WHERE test_run_id = ? ORDER BY timestamp`, r.testRunID)
	if err != nil {
		return 0
	}
	defer rows.Close()

	var longest, current int64
	pollIntervalMs := int64(10000) // 10s default

	for rows.Next() {
		var responsive int
		var rtMs int64
		if err := rows.Scan(&responsive, &rtMs); err != nil {
			continue
		}
		if responsive == 0 {
			current += pollIntervalMs
			if current > longest {
				longest = current
			}
		} else {
			current = 0
		}
	}
	return longest
}

func (r *Reporter) fillChaosResults(rpt *StressTestReport) {
	rpt.ChaosResults.ByType = make(map[string]int64)
	rpt.ChaosResults.RecoveryTimeByType = make(map[string]LatencyStats)

	// Count by type
	rows, err := r.db.Query(`SELECT type, COUNT(*) FROM chaos_events
		WHERE test_run_id = ? GROUP BY type`, r.testRunID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ct string
		var count int64
		if err := rows.Scan(&ct, &count); err != nil {
			continue
		}
		rpt.ChaosResults.ByType[ct] = count
		rpt.ChaosResults.TotalInjections += count
	}

	// Max recovery time
	var maxRecovery sql.NullInt64
	r.db.QueryRow(`SELECT MAX(recovery_time_ms) FROM chaos_events
		WHERE test_run_id = ? AND recovery_time_ms > 0`, r.testRunID).Scan(&maxRecovery)
	if maxRecovery.Valid {
		rpt.ChaosResults.MaxRecoveryTimeMs = maxRecovery.Int64
	}

	// Recovery failures (recovery_time_ms > 30000 or NULL when expected)
	r.db.QueryRow(`SELECT COUNT(*) FROM chaos_events
		WHERE test_run_id = ? AND recovery_time_ms > 30000`, r.testRunID).Scan(
		&rpt.ChaosResults.RecoveryFailures)
}

func (r *Reporter) fillResourceManagement(rpt *StressTestReport) {
	r.db.QueryRow(`SELECT COUNT(*) FROM reaper_actions
		WHERE test_run_id = ? AND success = 1`, r.testRunID).Scan(&rpt.ResourceManagement.Reaped)

	// Created = count of successful mutate commands
	r.db.QueryRow(`SELECT COUNT(*) FROM command_results
		WHERE test_run_id = ? AND category = 'mutate' AND failure_class = ''`,
		r.testRunID).Scan(&rpt.ResourceManagement.Created)
}

func (r *Reporter) fillTimeline(rpt *StressTestReport) {
	rows, err := r.db.Query(`SELECT timestamp, category, description FROM timeline_events
		WHERE test_run_id = ? ORDER BY timestamp`, r.testRunID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tsStr, cat, desc string
		if err := rows.Scan(&tsStr, &cat, &desc); err != nil {
			continue
		}
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		rpt.Timeline = append(rpt.Timeline, TimelineEvent{
			Timestamp:   ts,
			Category:    cat,
			Description: desc,
		})
	}
}

func percentile(sorted []int64, pct int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(pct)/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// GenerateFromDB generates and prints a report from a DB file (for the report subcommand).
func GenerateFromDB(dbPath, runID string) error {
	db, err := metrics.OpenDB(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	if err := metrics.CheckSchemaVersion(db); err != nil {
		return err
	}

	if runID == "" {
		var err error
		runID, err = metrics.LatestRunID(db)
		if err != nil {
			return err
		}
	}

	reporter := NewReporter(db, runID, []int{50, 90, 95, 99})
	rpt := reporter.Generate()
	rpt.Verdict, rpt.Issues = DetermineVerdict(rpt, 500)

	data, err := json.MarshalIndent(rpt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
