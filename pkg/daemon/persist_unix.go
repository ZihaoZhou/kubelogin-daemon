//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// runtimeUserID returns a stable per-user identifier for the runtime directory name.
// On Unix, this is the numeric UID.
func runtimeUserID() string {
	return strconv.Itoa(os.Getuid())
}

// stableTempDir returns a fixed temp directory immune to $TMPDIR changes.
//
// On macOS, $TMPDIR is per-session (/var/folders/xx/.../T/) and is frequently
// overridden by scripts (TMPDIR=$(mktemp -d)), build systems, and containers.
// os.TempDir() reads $TMPDIR, so using it in RuntimeDir() causes the daemon
// and get-token to disagree on the socket path — breaking the singleton pattern
// and spawning orphan daemons with no cached tokens.
//
// /tmp is always available on Unix and is what gpg-agent/ssh-agent use.
func stableTempDir() string {
	return "/tmp"
}

// openNoFollow opens a file with O_NOFOLLOW, atomically rejecting symlinks.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// ELOOP means the path is a symlink (O_NOFOLLOW rejects it)
		if isELOOP(err) {
			return nil, fmt.Errorf("persist file is a symlink (rejected)")
		}
		return nil, err
	}
	return f, nil
}

// SEC-MED-9: Use errors.Is instead of manual unwrap. The manual version
// only handled *os.PathError, missing *fs.PathError, errors.Join, and
// other wrappers. errors.Is traverses the full error chain.
func isELOOP(err error) bool {
	return errors.Is(err, syscall.ELOOP)
}

// platformUID returns the current user's UID for peer verification.
// COMPAT-10: On Unix, os.Getuid() returns the real UID.
func platformUID() uint32 {
	return uint32(os.Getuid())
}

// fileInode returns the inode number of a file from its os.FileInfo.
// B2: Used to detect socket file deletion/replacement in idleWatcher.
func fileInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
