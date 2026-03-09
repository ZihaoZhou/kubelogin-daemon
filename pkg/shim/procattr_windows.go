//go:build windows

package shim

import "syscall"

// daemonSysProcAttr returns the SysProcAttr for starting a daemon process on Windows.
// CREATE_NEW_PROCESS_GROUP detaches the daemon from the parent console.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags:    0x00000200, // CREATE_NEW_PROCESS_GROUP
		NoInheritHandles: true,       // Prevent inheriting parent's handles (fd leak prevention)
	}
}
