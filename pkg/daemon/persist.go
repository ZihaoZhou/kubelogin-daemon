package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// validCacheKey matches hex strings (output of tokencache ComputeChecksum).
var validCacheKey = regexp.MustCompile(`^[a-fA-F0-9]{1,128}$`)

// IsValidCacheKey reports whether name looks like a valid cache key (hex string).
func IsValidCacheKey(name string) bool {
	return validCacheKey.MatchString(name)
}

// maxPersistFileSize is the maximum size of a persisted token file (10MB).
// SEC-5: Prevents OOM from reading attacker-crafted oversized files.
// 10MB is generous — a typical JWT is ~2KB; 10MB allows for unusually large
// tokens while still preventing multi-GB OOM attacks.
const maxPersistFileSize = 10 << 20

// persistedToken is the on-disk format for persisted tokens.
// Includes a format version for forward compatibility.
type persistedToken struct {
	FormatVersion int    `json:"format_version"`
	IDToken       string `json:"id_token,omitempty"`
	RefreshToken  string `json:"refresh_token,omitempty"`
}

const persistFormatVersion = 1

// RuntimeDir returns the per-machine runtime directory for the daemon.
// This is NEVER under $HOME to avoid NFS issues.
// On Unix: /tmp/kubelogin-daemon-$UID (or XDG_RUNTIME_DIR/kubelogin-daemon)
// On Windows: %TEMP%/kubelogin-daemon-$SID
//
// CRITICAL: The fallback uses stableTempDir() (NOT os.TempDir()) to avoid
// $TMPDIR sensitivity. On macOS, $TMPDIR is per-session and commonly overridden
// by scripts/build-systems, which would break the singleton pattern by causing
// the daemon and get-token to use different socket paths.
func RuntimeDir() string {
	// Prefer XDG_RUNTIME_DIR (typically /run/user/$UID on systemd systems, tmpfs)
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "kubelogin-daemon")
	}
	// Fallback: stableTempDir()/kubelogin-daemon-<userID>
	// stableTempDir() is platform-specific: /tmp on Unix, os.TempDir() on Windows
	// runtimeUserID() is platform-specific: UID on Unix, SID on Windows
	return filepath.Join(stableTempDir(), "kubelogin-daemon-"+runtimeUserID())
}

// PersistToken atomically writes a token to disk.
// Pattern: write temp file → fsync → rename (atomic on POSIX).
func PersistToken(dir, cacheKey, idToken, refreshToken string) error {
	if !validCacheKey.MatchString(cacheKey) {
		return fmt.Errorf("invalid cache key: must be hex string")
	}
	data := persistedToken{
		FormatVersion: persistFormatVersion,
		IDToken:       idToken,
		RefreshToken:  refreshToken,
	}
	b, err := json.Marshal(&data)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	// SEC-CRIT-2: Use os.Mkdir (not MkdirAll). mkdir(2) atomically rejects
	// symlinks (returns EEXIST), preventing TOCTOU attacks where an attacker
	// plants a symlink before the directory is created. MkdirAll follows
	// symlinks in intermediate path components.
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create persist dir: %w", err)
	}

	finalPath := filepath.Join(dir, cacheKey+".json")

	// Use os.CreateTemp for unique temp file names to prevent:
	// 1. Symlink attacks on predictable .tmp paths (token exfiltration)
	// 2. Data corruption from concurrent PersistToken calls for same cacheKey
	// CreateTemp uses O_EXCL internally, which fails on existing files/symlinks.
	f, err := os.CreateTemp(dir, cacheKey+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()

	// SEC-MED-4: Restrict temp file permissions immediately.
	// CreateTemp uses umask-based perms; on permissive umask the file could
	// be readable before Rename. The 0700 dir mitigates, but defense-in-depth.
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}

	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename to final path: %w", err)
	}

	// Harden file permissions (on Windows, 0600 is ignored; ACL is needed)
	if err := setPrivatePermissions(finalPath, false); err != nil {
		// Non-fatal: the file was already written, but log-worthy
		return fmt.Errorf("harden persist file permissions: %w", err)
	}
	return nil
}

// MigrateTokensFromLegacyDir copies persisted token files from the old
// TMPDIR-dependent path to the new stable RuntimeDir.
//
// Before the stableTempDir fix, RuntimeDir used os.TempDir() which on macOS
// resolves to /var/folders/.../T/. After the fix, it resolves to /tmp/.
// This one-time migration prevents users from losing cached tokens on upgrade.
//
// Only migrates files from directories owned by the current user with mode 0700.
func MigrateTokensFromLegacyDir(newDir string) {
	legacyDir := filepath.Join(os.TempDir(), "kubelogin-daemon-"+runtimeUserID())
	if legacyDir == newDir {
		return // same path, nothing to migrate
	}

	// SEC-10: Use Lstat (not Stat) to avoid following symlinks.
	// os.Stat follows symlinks, so an attacker-placed symlink would report
	// info about the target dir instead of the symlink itself.
	if info, err := os.Lstat(legacyDir); err != nil {
		return // no legacy dir
	} else if info.Mode()&os.ModeSymlink != 0 {
		return // symlink — refuse to migrate
	} else if !info.IsDir() {
		return // not a directory
	}
	if err := validateRuntimeDirSecurity(legacyDir); err != nil {
		return // not owned by us or wrong permissions — don't touch
	}

	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		return
	}

	migrated := 0
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		// Validate filename is a hex cache key (prevent path traversal)
		base := name[:len(name)-len(".json")]
		if !validCacheKey.MatchString(base) {
			continue
		}
		dst := filepath.Join(newDir, name)
		if _, err := os.Stat(dst); err == nil {
			continue // already exists at new path
		}
		src := filepath.Join(legacyDir, name)
		// SECURITY: Use Lstat to reject symlinks. An attacker who previously
		// compromised the legacy dir could plant symlinks to exfiltrate data
		// or inject tokens.
		srcInfo, err := os.Lstat(src)
		if err != nil {
			continue
		}
		if srcInfo.Mode()&os.ModeSymlink != 0 {
			continue // skip symlinks
		}
		if !srcInfo.Mode().IsRegular() {
			continue // skip non-regular files
		}
		// Use openNoFollow for defense in depth (atomic symlink rejection)
		f, err := openNoFollow(src)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxPersistFileSize))
		f.Close()
		if err != nil {
			continue
		}
		// SEC-MED-3: Use atomic temp+rename instead of os.WriteFile.
		// If interrupted mid-write, the destination would be corrupted.
		if err := atomicWriteFile(dst, data, 0600); err != nil {
			continue
		}
		// ROB-MED-2: Remove the source file after successful migration
		// instead of RemoveAll on the entire directory later.
		os.Remove(src)
		migrated++
	}

	// ROB-MED-4: Try to remove the legacy directory if it's now empty.
	// os.Remove (not RemoveAll) only succeeds on empty directories,
	// so non-token files (socket, nonce, log) are preserved.
	if migrated > 0 || len(entries) == 0 {
		os.Remove(legacyDir) // fails silently if non-empty
	}
}

// atomicWriteFile writes data to path using temp+rename for crash safety.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".migrate-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// LoadPersistedToken reads a persisted token from disk.
// Returns empty strings if the file does not exist or is corrupt.
// B3: Corrupt files are automatically deleted and treated as missing.
func LoadPersistedToken(dir, cacheKey string) (idToken, refreshToken string, err error) {
	if !validCacheKey.MatchString(cacheKey) {
		return "", "", fmt.Errorf("invalid cache key: must be hex string")
	}
	finalPath := filepath.Join(dir, cacheKey+".json")

	// Open the file, rejecting symlinks to prevent symlink-based token read attacks.
	// Uses platform-specific openNoFollow to avoid TOCTOU between lstat and read.
	f, err := openNoFollow(finalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	defer f.Close()

	// SEC-5: Limit read size to prevent OOM from oversized files.
	// ROB-MED-2: Read maxPersistFileSize+1 to detect truncation. If we get
	// the full amount, the file exceeds the limit and may have been truncated.
	b, err := io.ReadAll(io.LimitReader(f, maxPersistFileSize+1))
	if err != nil {
		return "", "", fmt.Errorf("read persist file: %w", err)
	}
	if int64(len(b)) > maxPersistFileSize {
		// B3: Oversized file — delete and return error (same treatment as corrupt JSON).
		// Without deletion, daemon restart would hit the same oversized file repeatedly.
		os.Remove(finalPath)
		return "", "", fmt.Errorf("persist file exceeds maximum size (%d bytes), deleted", maxPersistFileSize)
	}

	var data persistedToken
	if err := json.Unmarshal(b, &data); err != nil {
		// B3: Corrupt JSON — delete the file and return descriptive error.
		// The caller logs this at WARN level (B5 observability requirement).
		// File is deleted to prevent infinite retry on daemon restart.
		os.Remove(finalPath)
		return "", "", fmt.Errorf("corrupt persist file deleted: %w", err)
	}
	if data.FormatVersion != persistFormatVersion {
		// B3: Unknown format version — delete and return descriptive error.
		os.Remove(finalPath)
		return "", "", fmt.Errorf("persist file has unknown format version %d, deleted", data.FormatVersion)
	}
	return data.IDToken, data.RefreshToken, nil
}
