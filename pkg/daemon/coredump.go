//go:build !windows

package daemon

import "syscall"

// disableCoreDump sets RLIMIT_CORE to 0 to prevent tokens from being written to core dumps.
func disableCoreDump() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
