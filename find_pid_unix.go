//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// findPIDBySocket finds the PID of the process listening on a Unix socket.
// Used as a fallback when IPC-based PID lookup fails (e.g., nonce mismatch).
//
// On Linux: stats the socket to get its inode, then scans /proc/*/fd/* to find
// which process holds that inode. This is the same approach as "lsof" but
// without shelling out.
//
// On macOS/other: returns 0 (not supported without lsof, and shelling out
// to lsof is fragile). The caller should handle pid==0 gracefully.
func findPIDBySocket(socketPath string) int {
	// Get the socket's inode from stat.
	var stat syscall.Stat_t
	if err := syscall.Stat(socketPath, &stat); err != nil {
		return 0
	}
	targetIno := stat.Ino
	if targetIno == 0 {
		return 0 // macOS doesn't report meaningful inodes for sockets
	}

	// Scan /proc/*/fd/* for a symlink pointing to socket:[inode]
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0 // not Linux, or no /proc
	}

	myPID := os.Getpid()
	socketTarget := fmt.Sprintf("socket:[%d]", targetIno)

	for _, proc := range procs {
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue // not a PID directory
		}
		if pid == myPID {
			continue // skip ourselves
		}

		fdDir := filepath.Join("/proc", proc.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // permission denied or process exited
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(link, socketTarget) {
				return pid
			}
		}
	}

	return 0
}
