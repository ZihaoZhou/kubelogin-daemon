//go:build !windows

package shim

import (
	"fmt"
	"os"
	"path/filepath"
)

// AutoStartDaemon detects a missing/stale daemon and starts a new one.
// Uses the gpg-agent model: fork a detached process, wait for socket to be ready.
func AutoStartDaemon(runtimeDir string) error {
	return autoStartDaemonCommon(runtimeDir, cleanupStaleUnixSocket)
}

// cleanupStaleUnixSocket removes a stale Unix socket file if it exists.
// Called after TransportProbeAlive failed, so we know no daemon is listening.
func cleanupStaleUnixSocket(runtimeDir string) error {
	socketPath := filepath.Join(runtimeDir, "sock")
	info, err := os.Lstat(socketPath)
	if err != nil {
		return nil // no socket file, nothing to clean
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("socket path %s is a symlink (refusing to remove)", socketPath)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("socket path is not a socket (type: %s)", info.Mode().Type())
	}
	// Socket file exists but daemon isn't listening → stale, remove it.
	os.Remove(socketPath)
	return nil
}
