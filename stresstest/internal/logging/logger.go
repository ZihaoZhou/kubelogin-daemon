package logging

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger writes structured log lines to an append-only file and optionally to stderr.
type Logger struct {
	file    *os.File
	mu      sync.Mutex
	verbose bool
}

// New creates a new Logger writing to the given path.
func New(path string, verbose bool) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &Logger{file: f, verbose: verbose}, nil
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

func (l *Logger) write(level, msg string) {
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	line := fmt.Sprintf("%s [%s] %s\n", ts, level, msg)

	l.mu.Lock()
	l.file.WriteString(line)
	l.mu.Unlock()

	if l.verbose || level == "ERROR" || level == "WARN" {
		fmt.Fprint(os.Stderr, line)
	}
}

// Info logs an informational message.
func (l *Logger) Info(msg string) {
	l.write("INFO", msg)
}

// Infof logs a formatted informational message.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.write("INFO", fmt.Sprintf(format, args...))
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string) {
	l.write("WARN", msg)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.write("WARN", fmt.Sprintf(format, args...))
}

// Error logs an error message.
func (l *Logger) Error(msg string) {
	l.write("ERROR", msg)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.write("ERROR", fmt.Sprintf(format, args...))
}
