package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestB3_CorruptJSON_DeletedAndReturnsEmpty verifies that LoadPersistedToken
// deletes a corrupt JSON file and returns empty strings (not an error).
func TestB3_CorruptJSON_DeletedAndReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	// Create a strict 0700 dir for token storage
	rtDir := filepath.Join(dir, "rt")
	if err := os.Mkdir(rtDir, 0700); err != nil {
		t.Fatal(err)
	}

	cacheKey := "abcdef1234567890"
	strategies := map[string][]byte{
		"random_bytes":  {0xff, 0xfe, 0x00, 0x01, 0x80},
		"empty":         {},
		"truncated_json": []byte(`{"format_version":1,"id_to`),
		"wrong_version": []byte(`{"format_version":999,"id_token":"x","refresh_token":"y"}`),
	}

	for name, data := range strategies {
		t.Run(name, func(t *testing.T) {
			filePath := filepath.Join(rtDir, cacheKey+".json")

			// Write corrupt data
			if err := os.WriteFile(filePath, data, 0600); err != nil {
				t.Fatal(err)
			}

			// Verify file exists
			if _, err := os.Stat(filePath); err != nil {
				t.Fatalf("file should exist before load: %v", err)
			}

			// Load — should return empty strings with a descriptive error
			// (B5: error is logged by caller at WARN level for observability).
			// The corrupt file should be deleted to prevent restart loops.
			idToken, refreshToken, err := LoadPersistedToken(rtDir, cacheKey)
			if err == nil {
				t.Fatalf("LoadPersistedToken should return error for corrupt file")
			}
			t.Logf("corrupt file error (expected): %v", err)
			if idToken != "" || refreshToken != "" {
				t.Fatalf("expected empty tokens, got id=%q refresh=%q", idToken, refreshToken)
			}

			// Verify corrupt file was deleted
			if _, err := os.Stat(filePath); !os.IsNotExist(err) {
				t.Fatalf("corrupt file should have been deleted, stat err=%v", err)
			}
		})
	}
}

// TestB3_ValidFile_NotDeleted verifies that a valid persist file is NOT deleted.
func TestB3_ValidFile_NotDeleted(t *testing.T) {
	dir := t.TempDir()
	rtDir := filepath.Join(dir, "rt")
	if err := os.Mkdir(rtDir, 0700); err != nil {
		t.Fatal(err)
	}

	cacheKey := "abcdef1234567890"
	// First persist a valid token
	if err := PersistToken(rtDir, cacheKey, "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.sig", "valid-refresh"); err != nil {
		t.Fatal(err)
	}

	idToken, refreshToken, err := LoadPersistedToken(rtDir, cacheKey)
	if err != nil {
		t.Fatalf("valid file returned error: %v", err)
	}
	if refreshToken != "valid-refresh" {
		t.Fatalf("expected refresh token 'valid-refresh', got %q", refreshToken)
	}
	if idToken == "" {
		t.Fatal("expected non-empty id token")
	}

	// File should still exist
	filePath := filepath.Join(rtDir, cacheKey+".json")
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("valid file should not be deleted: %v", err)
	}
}

// TestB3_EmptyRefreshToken_PermanentError verifies that Refresh returns a
// permanent (non-retryable) error when the refresh token is empty.
func TestB3_EmptyRefreshToken_PermanentError(t *testing.T) {
	dir := t.TempDir()
	rtDir := filepath.Join(dir, "rt")
	if err := os.Mkdir(rtDir, 0700); err != nil {
		t.Fatal(err)
	}

	logDir := filepath.Join(dir, "log")
	if err := os.Mkdir(logDir, 0700); err != nil {
		t.Fatal(err)
	}
	logger, err := NewLogger(logDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()

	// Create a mock refresher that should never be called
	callCount := 0
	mock := &corruptTestRefresher{
		refreshFn: func(ctx context.Context, rt string) (string, string, time.Time, error) {
			callCount++
			t.Fatal("refresher should not be called with empty refresh token")
			return "", "", time.Time{}, nil
		},
	}

	tm := NewTokenManager(TokenManagerConfig{
		Refresher:  mock,
		PersistDir: rtDir,
		CacheKey:   "test",
		Logger:     logger,
	})
	defer tm.Stop()

	// Set a token entry with empty refresh token
	tm.current.Store(&tokenEntry{
		idToken:      "some-id-token",
		refreshToken: "", // empty!
		expiry:       time.Now().Add(-time.Hour),
		obtainedAt:   time.Now(),
	})

	ctx := context.Background()
	_, _, err = tm.Refresh(ctx)
	if err == nil {
		t.Fatal("expected error from Refresh with empty refresh token")
	}

	if !IsPermanentRefreshError(err) {
		t.Fatalf("expected permanent refresh error, got: %v", err)
	}

	if callCount != 0 {
		t.Fatalf("refresher was called %d times (expected 0)", callCount)
	}
}

// corruptTestRefresher is a test helper implementing the Refresher interface.
type corruptTestRefresher struct {
	refreshFn func(ctx context.Context, refreshToken string) (string, string, time.Time, error)
}

func (m *corruptTestRefresher) Refresh(ctx context.Context, refreshToken string) (string, string, time.Time, error) {
	return m.refreshFn(ctx, refreshToken)
}
