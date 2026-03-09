package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistAndLoad(t *testing.T) {
	dir := t.TempDir()

	cacheKey := "abcdef1234567890"
	idToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxOTk5OTk5OTk5fQ.sig"
	refreshToken := "refresh-token-123"

	// Persist
	if err := PersistToken(dir, cacheKey, idToken, refreshToken); err != nil {
		t.Fatalf("PersistToken: %v", err)
	}

	// Verify file exists with correct permissions
	path := filepath.Join(dir, cacheKey+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("want perms 0600, got %o", perm)
	}

	// Load
	gotID, gotRT, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Fatalf("LoadPersistedToken: %v", err)
	}
	if gotID != idToken {
		t.Errorf("id_token: want %q, got %q", idToken, gotID)
	}
	if gotRT != refreshToken {
		t.Errorf("refresh_token: want %q, got %q", refreshToken, gotRT)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()

	gotID, gotRT, err := LoadPersistedToken(dir, "aabbccdd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotID != "" || gotRT != "" {
		t.Errorf("expected empty strings for missing file, got id=%q rt=%q", gotID, gotRT)
	}
}

func TestPersistAtomic_NoTempFileLeftOver(t *testing.T) {
	dir := t.TempDir()

	if err := PersistToken(dir, "aabb1122", "id", "rt"); err != nil {
		t.Fatalf("PersistToken: %v", err)
	}

	// Verify no .tmp file left over
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left over: %s", e.Name())
		}
	}
}

func TestPersistOverwrite(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "ff00ff00"

	// Write first version
	if err := PersistToken(dir, cacheKey, "id1", "rt1"); err != nil {
		t.Fatalf("first persist: %v", err)
	}

	// Overwrite with second version
	if err := PersistToken(dir, cacheKey, "id2", "rt2"); err != nil {
		t.Fatalf("second persist: %v", err)
	}

	// Load should return second version
	gotID, gotRT, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotID != "id2" || gotRT != "rt2" {
		t.Errorf("want id2/rt2, got %q/%q", gotID, gotRT)
	}
}

func TestLoadUnknownFormatVersion(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "deadbeef"
	path := filepath.Join(dir, cacheKey+".json")
	// Write a file with format_version=99
	if err := os.WriteFile(path, []byte(`{"format_version":99,"id_token":"x","refresh_token":"y"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	gotID, gotRT, err := LoadPersistedToken(dir, cacheKey)
	// B3: Unknown version returns a descriptive error (file was deleted).
	// Callers log this and treat as "no token".
	if err == nil {
		t.Fatal("expected error for unknown format version")
	}
	t.Logf("expected error: %v", err)
	// Tokens should be empty
	if gotID != "" || gotRT != "" {
		t.Errorf("unknown version should return empty, got id=%q rt=%q", gotID, gotRT)
	}
}

func TestPersistInvalidCacheKey(t *testing.T) {
	dir := t.TempDir()
	// Path traversal attempt
	if err := PersistToken(dir, "../../../etc/passwd", "id", "rt"); err == nil {
		t.Error("expected error for path traversal cache key")
	}
	// Non-hex characters
	if err := PersistToken(dir, "test-key", "id", "rt"); err == nil {
		t.Error("expected error for non-hex cache key")
	}
}

func TestRuntimeDir_NeverHome(t *testing.T) {
	dir := RuntimeDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home dir: %v", err)
	}
	// RuntimeDir must never be under $HOME (NFS safety)
	if len(dir) >= len(home) && dir[:len(home)] == home {
		t.Errorf("RuntimeDir %q is under $HOME %q (NFS unsafe)", dir, home)
	}
}
