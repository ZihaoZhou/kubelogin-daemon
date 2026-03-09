//go:build !windows

package shim

import "syscall"

// daemonSysProcAttr returns the SysProcAttr for forking a daemon process.
// Setsid creates a new session so the daemon survives parent exit.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
