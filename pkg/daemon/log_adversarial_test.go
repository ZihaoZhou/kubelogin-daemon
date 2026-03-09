package daemon

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// Attack vector: JWT-like strings that should be sanitized in log output.
func TestAdversarial_Log_SanitizeJWT(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		mustRedact bool
	}{
		{"standard JWT", "token is eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig", true},
		{"JWT at start", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig in message", true},
		{"short eyJ", "eyJab is too short", false}, // < 10 chars should not be redacted
		{"just eyJ", "eyJ", false},
		{"embedded in URL", "https://example.com/eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig", true},
		{"multiple JWTs", "first eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig and second eyJhbGciOiJSUzI1NiJ9.eyJkYXRhIjoiMiJ9.sig2", true},
		{"no JWT", "normal log message without tokens", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitize(tc.input)
			if tc.mustRedact {
				if strings.Contains(result, "eyJ") && !strings.Contains(result, "[REDACTED]") {
					t.Errorf("JWT not redacted: input=%q, output=%q", tc.input, result)
				}
			}
			if strings.Contains(result, "eyJhbGciOiJSUzI1NiJ9") {
				t.Errorf("JWT payload leaked through sanitizer: %q", result)
			}
		})
	}
}

// Attack vector: Craft a string that looks like a JWT but isn't, to bypass sanitization.
func TestAdversarial_Log_SanitizeBypass(t *testing.T) {
	// These are NOT JWTs but start with "eyJ" — the sanitizer might redact them unnecessarily
	falsePositives := []struct {
		name  string
		input string
	}{
		{"short eyJ prefix", "eyJabcdefghijk is not a JWT"},
		{"filename", "loading file eyJhbGciOiJSUzI1NiJ9_token.json"},
	}

	for _, tc := range falsePositives {
		result := sanitize(tc.input)
		if strings.Contains(result, "[REDACTED]") {
			t.Logf("FINDING: sanitizer redacted non-JWT content: %q -> %q", tc.input, result)
		}
	}
}

// Attack vector: Token embedded in JSON structure in log message.
func TestAdversarial_Log_SanitizeJSONEmbedded(t *testing.T) {
	input := `{"token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig","status":"ok"}`
	result := sanitize(input)
	if strings.Contains(result, "eyJhbGciOiJSUzI1NiJ9") {
		t.Errorf("JWT in JSON not sanitized: %q", result)
	}
}

// Attack vector: Very long string with many eyJ occurrences.
func TestAdversarial_Log_SanitizeManyTokens(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString("token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig ")
	}
	input := builder.String()
	result := sanitize(input)
	if strings.Contains(result, "eyJhbGciOiJSUzI1NiJ9") {
		t.Error("not all JWTs were sanitized")
	}
}

// Attack vector: Concurrent log writes to test thread safety.
func TestAdversarial_Log_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	const goroutines = 100
	const writesPerGoroutine = 100
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				switch i % 3 {
				case 0:
					logger.Infof("goroutine %d info %d", id, i)
				case 1:
					logger.Warnf("goroutine %d warn %d", id, i)
				case 2:
					logger.Errorf("goroutine %d error %d", id, i)
				}
			}
		}(g)
	}
	wg.Wait()
}

// Attack vector: Logger with log file exceeding MaxLogSize.
func TestAdversarial_Log_Truncation(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	// Write enough data to exceed MaxLogSize (1MB)
	bigMsg := strings.Repeat("A", 1024) // 1KB per message
	for i := 0; i < 2000; i++ {         // 2MB total
		logger.Infof("%s", bigMsg)
	}

	// Log file should exist and not be too large
	logPath := dir + "/daemon.log"
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if info.Size() > 2*MaxLogSize {
		t.Errorf("log file too large after truncation: %d bytes (max should be ~%d)", info.Size(), MaxLogSize)
	}
}

// Attack vector: Logger with closed file handle.
func TestAdversarial_Log_WriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	logger.Close()
	// Writing after close — should not panic
	logger.Infof("test after close")
	logger.Warnf("warn after close")
	logger.Errorf("error after close")
}

// Attack vector: Format string injection in log messages.
func TestAdversarial_Log_FormatStringInjection(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLogger(dir, true)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	// These should not cause panics (fmt.Sprintf handles mismatched args)
	logger.Infof("normal %s message", "value")
	logger.Infof("message with %% percent sign")
	logger.Infof("message with literal %%s specifier")
}

// Attack vector: NewStderrLogger.
func TestAdversarial_Log_StderrLogger(t *testing.T) {
	logger := NewStderrLogger(true)
	logger.Infof("test message")
	logger.Close() // should not close os.Stderr

	// Verify stderr still works
	logger2 := NewStderrLogger(false)
	logger2.Warnf("should still work")
	logger2.Close()
}

// Attack vector: sanitize with string that has only base64url chars.
func TestAdversarial_Log_SanitizePureBase64(t *testing.T) {
	// A long base64url string starting with eyJ should be redacted
	longBase64 := "eyJ" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.", 100)
	result := sanitize(longBase64)
	if !strings.Contains(result, "[REDACTED]") {
		t.Error("long base64url string starting with eyJ should be redacted")
	}
}
