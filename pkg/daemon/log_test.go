package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogSanitization(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// Log a message containing a JWT-like token
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
	logger.Infof("got token: %s", jwt)
	logger.Close()

	// Read the log file and verify the token was redacted
	logPath := filepath.Join(dir, "daemon.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	logStr := string(content)
	if strings.Contains(logStr, "eyJ") {
		t.Errorf("log contains unredacted JWT token: %s", logStr)
	}
	if !strings.Contains(logStr, "[REDACTED]") {
		t.Errorf("log should contain [REDACTED] placeholder, got: %s", logStr)
	}
}

func TestLogSanitization_NoFalsePositive(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	// Normal messages should not be redacted
	logger.Infof("daemon started on /tmp/kubelogin-daemon-501/sock")
	logger.Close()

	logPath := filepath.Join(dir, "daemon.log")
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}

	logStr := string(content)
	if strings.Contains(logStr, "[REDACTED]") {
		t.Errorf("normal message was falsely redacted: %s", logStr)
	}
	if !strings.Contains(logStr, "daemon started") {
		t.Errorf("normal message should appear in log, got: %s", logStr)
	}
}
