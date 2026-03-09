//go:build windows

package shim

// AutoStartDaemon detects a missing/stale daemon and starts a new one.
// Windows named pipes are kernel-managed — no stale cleanup needed.
func AutoStartDaemon(runtimeDir string) error {
	return autoStartDaemonCommon(runtimeDir, nil)
}
