package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Attack vector: Symlink on the final token path — LoadPersistedToken
// should reject it via O_NOFOLLOW.
func TestAdversarial_Persist_SymlinkAttack(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "aabbccdd"

	// Create a symlink where the token file would be
	targetPath := filepath.Join(dir, "stolen-tokens")
	os.WriteFile(targetPath, []byte(`{"format_version":1,"id_token":"stolen","refresh_token":"rt"}`), 0600)

	finalPath := filepath.Join(dir, cacheKey+".json")
	if err := os.Symlink(targetPath, finalPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// LoadPersistedToken should reject the symlink
	_, _, err := LoadPersistedToken(dir, cacheKey)
	if err == nil {
		t.Error("VULNERABILITY: LoadPersistedToken should reject symlink paths")
	} else {
		t.Logf("correctly rejected symlink: %v", err)
	}
}

// Attack vector: Symlink on the .tmp file during PersistToken.
// If an attacker pre-creates a symlink at the .tmp path, the daemon
// would write tokens to an attacker-controlled location.
func TestAdversarial_Persist_SymlinkOnTmpFile(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "aabbccdd"

	// Pre-create a symlink at the .tmp path pointing to attacker location
	attackerFile := filepath.Join(dir, "attacker-controlled")
	tmpPath := filepath.Join(dir, cacheKey+".json.tmp")
	if err := os.Symlink(attackerFile, tmpPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	// PersistToken uses O_WRONLY|O_CREATE|O_TRUNC — this will follow the symlink
	err := PersistToken(dir, cacheKey, "id-token", "refresh-token")
	if err == nil {
		// Check if the attacker-controlled file now has our token
		data, readErr := os.ReadFile(attackerFile)
		if readErr == nil && strings.Contains(string(data), "id-token") {
			t.Error("VULNERABILITY: PersistToken followed symlink on .tmp file, wrote tokens to attacker-controlled path")
		}
	} else {
		t.Logf("PersistToken rejected symlink on .tmp: %v", err)
	}
}

// Attack vector: Corrupt JSON in persisted file.
func TestAdversarial_Persist_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "deadbeef"

	corruptData := []string{
		"",                    // empty
		"{",                   // incomplete
		"null",                // valid JSON but wrong type
		"[]",                  // array not object
		`{"format_version":}`, // invalid syntax
		`{"format_version":1,"id_token":"x","refresh_token":"y","extra":"field"}`, // extra field
		string(make([]byte, 0)),          // truly empty
		"\x00\x00\x00",                   // binary garbage
		`{"format_version":1,"id_token":` + strings.Repeat("A", 10<<20) + `}`, // 10MB value
	}

	for i, data := range corruptData {
		path := filepath.Join(dir, cacheKey+".json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatalf("write corrupt data %d: %v", i, err)
		}

		_, _, err := LoadPersistedToken(dir, cacheKey)
		// Should not panic, should return an error for most
		if err != nil {
			t.Logf("corrupt data %d: correctly returned error: %v", i, err)
		} else {
			t.Logf("corrupt data %d: returned no error (may be acceptable)", i)
		}
	}
}

// Attack vector: Cache key with path traversal attempts that pass the hex regex.
func TestAdversarial_Persist_CacheKeyInjection(t *testing.T) {
	dir := t.TempDir()

	// These should all be rejected by the hex regex
	badKeys := []string{
		"../../../etc/passwd",
		"..%2F..%2Fetc/passwd",
		"test\x00null",  // null byte injection
		"test key",      // space
		"test/key",      // slash
		"test\\key",     // backslash
		"ZZZZ",          // uppercase non-hex
		"gggg",          // lowercase non-hex
		"",              // empty
		".",             // current dir
		"..",            // parent dir
		"a" + strings.Repeat("b", 200), // too long (>128 hex chars)
	}

	for _, key := range badKeys {
		err := PersistToken(dir, key, "id", "rt")
		if err == nil {
			t.Errorf("VULNERABILITY: PersistToken accepted bad cache key %q", key)
		}
	}

	for _, key := range badKeys {
		_, _, err := LoadPersistedToken(dir, key)
		if err == nil {
			// Check if it actually returned empty (which is OK for missing file)
			// The key validation should reject it before even trying to read
			t.Logf("LoadPersistedToken accepted bad key %q (may have returned empty)", key)
		}
	}
}

// Attack vector: Valid hex strings at boundary lengths.
func TestAdversarial_Persist_CacheKeyBoundaryLengths(t *testing.T) {
	dir := t.TempDir()

	// Should accept: 1 char hex
	if err := PersistToken(dir, "a", "id", "rt"); err != nil {
		t.Errorf("single-char hex key should be valid: %v", err)
	}

	// Should accept: 128 char hex (max)
	key128 := strings.Repeat("ab", 64) // 128 chars
	if err := PersistToken(dir, key128, "id", "rt"); err != nil {
		t.Errorf("128-char hex key should be valid: %v", err)
	}

	// Should reject: 129 char hex
	key129 := strings.Repeat("ab", 64) + "c" // 129 chars
	if err := PersistToken(dir, key129, "id", "rt"); err == nil {
		t.Error("129-char hex key should be rejected")
	}
}

// Attack vector: Concurrent PersistToken on the same key.
// Bug found: Multiple goroutines call PersistToken with the same cache key.
// They all write to the same .tmp file concurrently (no per-caller temp file),
// causing data corruption. The final file may contain interleaved JSON.
func TestAdversarial_Persist_ConcurrentReadWrite(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "aabb1122"
	const goroutines = 50
	var wg sync.WaitGroup
	var writeErrors, readErrors int32

	wg.Add(goroutines * 2)

	// Concurrent writers — all writing to the same .tmp file
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			idToken := fmt.Sprintf("token-%04d", id)
			if err := PersistToken(dir, cacheKey, idToken, "rt"); err != nil {
				t.Logf("write error: %v", err)
			}
		}(g)
	}

	// Concurrent readers
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			_, _, err := LoadPersistedToken(dir, cacheKey)
			if err != nil {
				// Corrupt data from concurrent writes
				t.Logf("concurrent read error: %v", err)
			}
		}()
	}

	wg.Wait()
	_ = writeErrors
	_ = readErrors

	// After all writers finish, the file should be valid.
	// BUG: It might be corrupt because concurrent PersistToken calls
	// share the same .tmp path and can write interleaved data.
	_, rt, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Errorf("BUG CONFIRMED: Concurrent PersistToken corrupted the final file: %v", err)
		t.Log("Root cause: All PersistToken calls use the same .tmp file path. Two concurrent writers " +
			"can interleave their writes to the .tmp file, then one rename clobbers the other.")
	} else if rt != "rt" {
		t.Errorf("final refresh token mismatch: %q", rt)
	}
}

// Attack vector: Unicode and special characters in token values.
func TestAdversarial_Persist_SpecialCharTokens(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "ff00ff00"

	specialTokens := []struct {
		name string
		tok  string
	}{
		{"null bytes", "token\x00with\x00nulls"},
		{"unicode", "token\u4e2d\u6587\u65e5\u672c\u8a9e"},
		{"newlines", "token\nwith\nnewlines"},
		{"tabs", "token\twith\ttabs"},
		{"quotes", `token"with"quotes`},
		{"backslashes", `token\with\backslashes`},
		{"html", "<script>alert('xss')</script>"},
		{"very long", strings.Repeat("x", 1<<20)}, // 1MB token
	}

	for _, tc := range specialTokens {
		err := PersistToken(dir, cacheKey, tc.tok, "rt")
		if err != nil {
			t.Logf("%s: PersistToken error: %v", tc.name, err)
			continue
		}

		gotID, _, err := LoadPersistedToken(dir, cacheKey)
		if err != nil {
			t.Errorf("%s: LoadPersistedToken error: %v", tc.name, err)
			continue
		}
		if gotID != tc.tok {
			t.Errorf("%s: roundtrip mismatch", tc.name)
		}
	}
}

// Attack vector: Format version edge cases.
func TestAdversarial_Persist_FormatVersionEdgeCases(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "ee11ee11"

	versions := []struct {
		name    string
		version interface{}
		wantErr bool
	}{
		// B3: Unknown format versions return descriptive errors (file deleted).
		{"zero", 0, true},
		{"negative", -1, true},
		{"max int", 2147483647, true},
		{"float", 1.5, true}, // JSON unmarshal rejects float into int field
	}

	for _, tc := range versions {
		data := map[string]interface{}{
			"format_version": tc.version,
			"id_token":       "id-tok",
			"refresh_token":  "rt-tok",
		}
		b, _ := json.Marshal(data)
		path := filepath.Join(dir, cacheKey+".json")
		os.WriteFile(path, b, 0600)

		gotID, gotRT, err := LoadPersistedToken(dir, cacheKey)
		if err != nil {
			if !tc.wantErr {
				t.Errorf("%s: unexpected error: %v", tc.name, err)
			}
			t.Logf("%s: expected error: %v", tc.name, err)
		} else if tc.wantErr {
			t.Errorf("%s: expected error but got none", tc.name)
		}
		// All non-version-1 cases should return empty tokens
		if gotID != "" || gotRT != "" {
			t.Errorf("%s: expected empty tokens, got id=%q rt=%q", tc.name, gotID, gotRT)
		}
		// B3: Corrupt/unknown files should be deleted
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s: file should have been deleted", tc.name)
		}
	}
}

// Attack vector: Read-only directory — PersistToken should fail gracefully.
func TestAdversarial_Persist_ReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "aabb0011"

	// First write should work
	if err := PersistToken(dir, cacheKey, "id", "rt"); err != nil {
		t.Fatalf("initial persist: %v", err)
	}

	// Make directory read-only
	if err := os.Chmod(dir, 0500); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })

	// Second write should fail, not panic
	err := PersistToken(dir, cacheKey, "id2", "rt2")
	if err == nil {
		t.Error("PersistToken should fail on read-only directory")
	}

	// Original file should still be readable
	os.Chmod(dir, 0700) // restore for reading
	gotID, _, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Errorf("load after failed write: %v", err)
	}
	if gotID != "id" {
		t.Errorf("original token should be preserved after failed overwrite, got %q", gotID)
	}
}

// Attack vector: Token file with wrong permissions.
func TestAdversarial_Persist_WrongPermissions(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "ccdd0011"

	// Write normally
	if err := PersistToken(dir, cacheKey, "id", "rt"); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// Make file world-readable (security issue)
	path := filepath.Join(dir, cacheKey+".json")
	os.Chmod(path, 0644)

	// Load should still work (it doesn't validate permissions)
	_, _, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Errorf("load with wrong perms: %v", err)
	}
	t.Log("FINDING: LoadPersistedToken doesn't validate file permissions — will read world-readable token files")
}

// Attack vector: Nonexistent directory in LoadPersistedToken.
func TestAdversarial_Persist_NonexistentDir(t *testing.T) {
	_, _, err := LoadPersistedToken("/nonexistent/path/that/doesnt/exist", "aabb1122")
	if err != nil {
		t.Logf("nonexistent dir error: %v", err)
	}
	// Should return empty, not panic
}

// Attack vector: Concurrent PersistToken creating the directory at the same time.
func TestAdversarial_Persist_ConcurrentDirCreation(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "new", "nested", "dir")
	const goroutines = 20
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			// Use valid hex key unique per goroutine
			hexKey := fmt.Sprintf("%016x", id)
			PersistToken(dir, hexKey, "id", "rt")
		}(g)
	}
	wg.Wait()
}

// Attack vector: Extra JSON fields in persist file (DisallowUnknownFields
// is NOT used in LoadPersistedToken unlike server.go).
func TestAdversarial_Persist_ExtraJSONFields(t *testing.T) {
	dir := t.TempDir()
	cacheKey := "aabb2233"

	// Write a file with extra fields
	data := `{"format_version":1,"id_token":"id","refresh_token":"rt","malicious_field":"pwned","nested":{"deep":"value"}}`
	path := filepath.Join(dir, cacheKey+".json")
	os.WriteFile(path, []byte(data), 0600)

	gotID, gotRT, err := LoadPersistedToken(dir, cacheKey)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if gotID != "id" || gotRT != "rt" {
		t.Errorf("wrong values: id=%q rt=%q", gotID, gotRT)
	}
	// LoadPersistedToken does NOT use DisallowUnknownFields, so extra fields
	// are silently ignored. This is inconsistent with the server's handling.
	t.Log("FINDING: LoadPersistedToken silently ignores extra JSON fields (no DisallowUnknownFields)")
}
