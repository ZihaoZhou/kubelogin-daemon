package metrics

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS command_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    test_run_id   TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    category      TEXT NOT NULL,
    command_type  TEXT NOT NULL,
    args_json     TEXT,
    exit_code     INTEGER,
    duration_ms   INTEGER NOT NULL,
    failure_class TEXT NOT NULL DEFAULT '',
    error_text    TEXT,
    resource_name TEXT,
    sla_violation INTEGER NOT NULL DEFAULT 0,
    expect_client_error INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chaos_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    test_run_id      TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    type             TEXT NOT NULL,
    description      TEXT,
    duration_held_ms INTEGER,
    recovery_time_ms INTEGER
);

CREATE TABLE IF NOT EXISTS health_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    test_run_id      TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    pid              INTEGER,
    uptime_s         INTEGER,
    memory_rss       INTEGER,
    token_count      INTEGER,
    responsive       INTEGER NOT NULL,
    response_time_ms INTEGER,
    probe_mode       TEXT NOT NULL DEFAULT 'socket'
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    test_run_id TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    category    TEXT NOT NULL,
    description TEXT,
    metadata    TEXT
);

CREATE TABLE IF NOT EXISTS reaper_actions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    test_run_id   TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    age_s         INTEGER,
    success       INTEGER NOT NULL,
    error_text    TEXT
);

CREATE INDEX IF NOT EXISTS idx_cmd_run  ON command_results(test_run_id);
CREATE INDEX IF NOT EXISTS idx_cmd_cat  ON command_results(test_run_id, category);
CREATE INDEX IF NOT EXISTS idx_cmd_ts   ON command_results(test_run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_health   ON health_snapshots(test_run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline ON timeline_events(test_run_id, timestamp);
`

// OpenDB opens a SQLite database and creates the schema.
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Set pragmas for performance and safety
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("set pragma %q: %w", p, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	// Insert schema version if not present
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		db.Close()
		return nil, fmt.Errorf("check schema version: %w", err)
	}
	if count == 0 {
		if _, err := db.Exec("INSERT INTO schema_version VALUES (?)", schemaVersion); err != nil {
			db.Close()
			return nil, fmt.Errorf("insert schema version: %w", err)
		}
	}

	return db, nil
}

// CheckSchemaVersion verifies the DB schema version matches expectations.
func CheckSchemaVersion(db *sql.DB) error {
	var version int
	err := db.QueryRow("SELECT version FROM schema_version LIMIT 1").Scan(&version)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version != schemaVersion {
		return fmt.Errorf("schema version mismatch: expected %d, got %d", schemaVersion, version)
	}
	return nil
}
