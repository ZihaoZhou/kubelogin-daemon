package metrics

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Recorder writes structured metrics to SQLite with batching.
type Recorder struct {
	db        *sql.DB
	testRunID string

	// Batch buffer for command results (high throughput)
	cmdBuf []cmdRow
	cmdMu  sync.Mutex

	// Flush interval
	flushInterval time.Duration
	done          chan struct{}
	closeOnce     sync.Once
}

type cmdRow struct {
	Timestamp       time.Time
	Category        string
	CommandType     string
	ArgsJSON        string
	ExitCode        int
	DurationMs      int64
	FailureClass    string
	ErrorText       string
	ResourceName    string
	SLAViolation    bool
	ExpectClientErr bool
}

// NewRecorder creates a new Recorder.
func NewRecorder(db *sql.DB, testRunID string) *Recorder {
	r := &Recorder{
		db:            db,
		testRunID:     testRunID,
		cmdBuf:        make([]cmdRow, 0, 256),
		flushInterval: 1 * time.Second,
		done:          make(chan struct{}),
	}
	go r.flushLoop()
	return r
}

func (r *Recorder) flushLoop() {
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.flushCommands()
		case <-r.done:
			r.flushCommands()
			return
		}
	}
}

// Close flushes remaining data and stops the flush loop.
// Safe to call multiple times (idempotent).
func (r *Recorder) Close() {
	r.closeOnce.Do(func() {
		close(r.done)
	})
}

func (r *Recorder) flushCommands() {
	r.cmdMu.Lock()
	if len(r.cmdBuf) == 0 {
		r.cmdMu.Unlock()
		return
	}
	batch := r.cmdBuf
	r.cmdBuf = make([]cmdRow, 0, 256)
	r.cmdMu.Unlock()

	tx, err := r.db.Begin()
	if err != nil {
		return // best-effort
	}

	stmt, err := tx.Prepare(`INSERT INTO command_results
		(test_run_id, timestamp, category, command_type, args_json,
		 exit_code, duration_ms, failure_class, error_text, resource_name,
		 sla_violation, expect_client_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, row := range batch {
		sla := 0
		if row.SLAViolation {
			sla = 1
		}
		ece := 0
		if row.ExpectClientErr {
			ece = 1
		}
		_, _ = stmt.Exec(
			r.testRunID,
			row.Timestamp.UTC().Format(time.RFC3339Nano),
			row.Category,
			row.CommandType,
			row.ArgsJSON,
			row.ExitCode,
			row.DurationMs,
			row.FailureClass,
			row.ErrorText,
			row.ResourceName,
			sla,
			ece,
		)
	}
	tx.Commit()
}

// RecordResult records a command execution result.
func (r *Recorder) RecordResult(
	timestamp time.Time,
	category, commandType string,
	args []string,
	exitCode int,
	duration time.Duration,
	failureClass, errorText, resourceName string,
	slaViolation, expectClientError bool,
) {
	argsJSON, _ := json.Marshal(args)

	row := cmdRow{
		Timestamp:       timestamp,
		Category:        category,
		CommandType:     commandType,
		ArgsJSON:        string(argsJSON),
		ExitCode:        exitCode,
		DurationMs:      duration.Milliseconds(),
		FailureClass:    failureClass,
		ErrorText:       truncate(errorText, 1024),
		ResourceName:    resourceName,
		SLAViolation:    slaViolation,
		ExpectClientErr: expectClientError,
	}

	r.cmdMu.Lock()
	r.cmdBuf = append(r.cmdBuf, row)
	r.cmdMu.Unlock()
}

// RecordChaos records a chaos event (low frequency, direct insert).
func (r *Recorder) RecordChaos(
	timestamp time.Time,
	chaosType, description string,
	durationHeld, recoveryTime time.Duration,
) {
	_, _ = r.db.Exec(`INSERT INTO chaos_events
		(test_run_id, timestamp, type, description, duration_held_ms, recovery_time_ms)
		VALUES (?, ?, ?, ?, ?, ?)`,
		r.testRunID,
		timestamp.UTC().Format(time.RFC3339Nano),
		chaosType,
		description,
		durationHeld.Milliseconds(),
		recoveryTime.Milliseconds(),
	)
}

// RecordHealth records a health snapshot (low frequency, direct insert).
func (r *Recorder) RecordHealth(
	timestamp time.Time,
	pid int,
	uptimeS int64,
	memoryRSS int64,
	tokenCount int,
	responsive bool,
	responseTimeMs int64,
	probeMode string,
) {
	resp := 0
	if responsive {
		resp = 1
	}
	_, _ = r.db.Exec(`INSERT INTO health_snapshots
		(test_run_id, timestamp, pid, uptime_s, memory_rss, token_count,
		 responsive, response_time_ms, probe_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.testRunID,
		timestamp.UTC().Format(time.RFC3339Nano),
		pid,
		uptimeS,
		memoryRSS,
		tokenCount,
		resp,
		responseTimeMs,
		probeMode,
	)
}

// RecordTimeline records a timeline event.
func (r *Recorder) RecordTimeline(category, description string, metadata ...string) {
	var meta string
	if len(metadata) > 0 {
		meta = metadata[0]
	}
	_, _ = r.db.Exec(`INSERT INTO timeline_events
		(test_run_id, timestamp, category, description, metadata)
		VALUES (?, ?, ?, ?, ?)`,
		r.testRunID,
		time.Now().UTC().Format(time.RFC3339Nano),
		category,
		description,
		meta,
	)
}

// RecordReaper records a reaper action.
func (r *Recorder) RecordReaper(
	resourceType, resourceName string,
	ageS int64,
	success bool,
	errorText string,
) {
	s := 0
	if success {
		s = 1
	}
	_, _ = r.db.Exec(`INSERT INTO reaper_actions
		(test_run_id, timestamp, resource_type, resource_name, age_s, success, error_text)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.testRunID,
		time.Now().UTC().Format(time.RFC3339Nano),
		resourceType,
		resourceName,
		ageS,
		s,
		errorText,
	)
}

// LatestRunID returns the most recent test run ID from the DB.
func LatestRunID(db *sql.DB) (string, error) {
	var runID string
	err := db.QueryRow(`SELECT test_run_id FROM timeline_events
		ORDER BY timestamp DESC LIMIT 1`).Scan(&runID)
	if err != nil {
		return "", fmt.Errorf("no test runs found: %w", err)
	}
	return runID, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
