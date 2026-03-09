//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"syscall"
)

// validateRuntimeDirSecurity checks that the runtime directory is:
//  1. Owned by the current user (UID match)
//  2. Has strict permissions (0700, no group/other access)
//
// Both checks are required. Permission-only checks are insufficient because
// RuntimeDir is under /tmp (world-writable). An attacker could pre-create
// /tmp/kubelogin-daemon-<UID>/ before the victim, creating a DoS or (on
// non-standard filesystems where chmod on non-owned dirs succeeds) a token leak.
//
// The ownership check makes this explicit rather than relying on chmod EPERM.
func validateRuntimeDirSecurity(path string) error {
	// SEC-CRIT-3: Use Lstat (not Stat) to avoid following symlinks.
	// An attacker could create a symlink at the runtime dir path pointing to
	// an attacker-controlled directory; os.Stat would report the target's info.
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("lstat runtime dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime directory %s is a symlink (possible attack)", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path %s is not a directory", path)
	}

	// Check ownership — defense against /tmp directory pre-creation attacks.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s (unsupported platform)", path)
	}
	if stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("runtime directory %s owned by uid %d, expected %d (possible directory pre-creation attack)",
			path, stat.Uid, os.Getuid())
	}

	// Check permissions — no group/other access.
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("runtime directory %s has insecure permissions %o (must be 0700)", path, info.Mode().Perm())
	}
	return nil
}

// setPrivatePermissions sets restrictive permissions on a file or directory.
// On Unix, this uses chmod 0600 for files and 0700 for directories.
func setPrivatePermissions(path string, isDir bool) error {
	mode := os.FileMode(0600)
	if isDir {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
