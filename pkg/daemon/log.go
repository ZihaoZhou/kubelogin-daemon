package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxLogSize is the maximum log file size before truncation (1MB).
const MaxLogSize = 1 << 20

// Logger provides a sanitized logger for the daemon.
// It never logs token values (strings starting with "eyJ").
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	verbose bool
}

// NewLogger creates a logger that writes to the given directory.
// SEC-6: Rejects symlinks at both the directory and log file path.
func NewLogger(dir string, verbose bool) (*Logger, error) {
	// SEC-6: Check the directory itself for symlinks before MkdirAll.
	// An attacker could symlink the directory to redirect log output elsewhere.
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("log dir %s is a symlink (refusing to write)", dir)
		}
	}
	// SEC-CRIT-2: Use os.Mkdir (not MkdirAll) — see persist.go for rationale.
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	path := filepath.Join(dir, "daemon.log")
	// Reject symlinks at the log path (defense against symlink attacks where
	// an attacker places a symlink before the daemon creates the log file,
	// causing log writes to overwrite an attacker-controlled target).
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("log file %s is a symlink (refusing to write)", path)
		}
	}
	// SEC-HIGH-2: Use openLogFileNoFollow to atomically reject symlinks on Unix.
	f, err := openLogFileNoFollow(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &Logger{file: f, path: path, verbose: verbose}, nil
}

// NewStderrLogger creates a logger that writes to stderr (for systemd mode).
func NewStderrLogger(verbose bool) *Logger {
	return &Logger{file: os.Stderr, verbose: verbose}
}

// FilePath returns the log file path (empty for stderr logger).
func (l *Logger) FilePath() string {
	return l.path
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && l.file != os.Stderr {
		return l.file.Close()
	}
	return nil
}

// Infof logs an info-level message (only if verbose).
func (l *Logger) Infof(format string, args ...any) {
	if l.verbose {
		l.write("INFO", format, args...)
	}
}

// Warnf logs a warning-level message (always).
func (l *Logger) Warnf(format string, args ...any) {
	l.write("WARN", format, args...)
}

// Errorf logs an error-level message (always).
func (l *Logger) Errorf(format string, args ...any) {
	l.write("ERROR", format, args...)
}

func (l *Logger) write(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	msg = sanitize(msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	line := fmt.Sprintf("%s [%s] %s\n", time.Now().Format("2006-01-02T15:04:05.000"), level, msg)

	// ROB-9: Rotate log file instead of truncating to preserve recent history.
	// Old log is kept as daemon.log.1 for post-mortem analysis.
	if l.file != os.Stderr {
		if info, err := l.file.Stat(); err == nil && info.Size() > MaxLogSize {
			if err := l.file.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "kubelogin-daemon: log close before rotate failed: %v\n", err)
			}
			// Rotate: rename current → .1, then create fresh log.
			backupPath := l.path + ".1"
			_ = os.Remove(backupPath)         // remove old backup
			_ = os.Rename(l.path, backupPath) // current → backup
			// SEC-CRIT-1: Re-check for symlinks before opening the new file.
			// Between Rename and OpenFile, an attacker could place a symlink
			// at l.path, redirecting log output to an arbitrary target.
			if sInfo, sErr := os.Lstat(l.path); sErr == nil && sInfo.Mode()&os.ModeSymlink != 0 {
				fmt.Fprintf(os.Stderr, "kubelogin-daemon: log path %s is a symlink after rotation (refusing)\n", l.path)
				l.file = os.Stderr
			} else {
				// SEC-HIGH-2: Use openLogFileNoFollow to close TOCTOU gap.
				f, err := openLogFileNoFollow(l.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
				if err != nil {
					fmt.Fprintf(os.Stderr, "kubelogin-daemon: failed to rotate log %s: %v\n", l.path, err)
					l.file = os.Stderr
				} else {
					l.file = f
					fmt.Fprintf(l.file, "%s [%s] log rotated (previous log: %s)\n",
						time.Now().Format("2006-01-02T15:04:05.000"), "INFO", backupPath)
				}
			}
		}
	}

	if _, err := fmt.Fprint(l.file, line); err != nil && l.file != os.Stderr {
		fmt.Fprintf(os.Stderr, "kubelogin-daemon: log write failed: %v\n", err)
	}
}

// sanitize removes JWT tokens and other sensitive data from log messages.
// SEC-8: Fixed bug where a short "eyJ" prefix caused the scanner to exit
// the outer loop entirely (via break), leaving subsequent real tokens unsanitized.
func sanitize(s string) string {
	// Replace anything that looks like a JWT (eyJ...) with [REDACTED]
	result := s
	offset := 0
	for offset < len(result) {
		idx := strings.Index(result[offset:], "eyJ")
		if idx < 0 {
			break
		}
		idx += offset // absolute position
		// Find the end of the JWT-like string (base64url chars: A-Z a-z 0-9 - _ .)
		end := idx + 3
		for end < len(result) {
			c := result[end]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
				c == '-' || c == '_' || c == '.' {
				end++
			} else {
				break
			}
		}
		if end-idx > 10 { // Only redact if it looks like a real token (>10 chars)
			result = result[:idx] + "[REDACTED]" + result[end:]
			offset = idx + len("[REDACTED]")
		} else {
			// Too short to be a token — advance past it and keep scanning
			offset = end
		}
	}
	return result
}
