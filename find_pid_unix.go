//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
// On macOS/other: falls back to lsof(1) to find the owning process.
// lsof is pre-installed on macOS and most BSDs.
func findPIDBySocket(socketPath string) int {
	// Get the socket's inode from stat.
	var stat syscall.Stat_t
	if err := syscall.Stat(socketPath, &stat); err != nil {
		return 0
	}
	targetIno := stat.Ino
	if targetIno == 0 {
		// macOS doesn't report meaningful inodes for Unix sockets.
		// Fall back to lsof to find the owning process.
		if runtime.GOOS == "darwin" {
			return findPIDByLsof(socketPath)
		}
		return 0
	}

	// Scan /proc/*/fd/* for a symlink pointing to socket:[inode]
	procs, err := os.ReadDir("/proc")
	if err != nil {
		// Not Linux (no /proc). Try lsof as fallback.
		return findPIDByLsof(socketPath)
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

// findPIDByLsof uses lsof to find the PID of the process listening on a Unix socket.
// This is the fallback for macOS and other systems without /proc.
// lsof is pre-installed on macOS and most BSDs.
func findPIDByLsof(socketPath string) int {
	// lsof -U -a -F p <path>
	//   -U: only Unix sockets
	//   -a: AND the filters (socket type AND path)
	//   -F p: machine-readable output, PID lines prefixed with 'p'
	// Timeout via context to avoid hanging on pathological lsof.
	cmd := exec.Command("lsof", "-U", "-a", "-F", "p", socketPath)
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return 0
	}

	myPID := os.Getpid()
	for _, line := range strings.Split(out.String(), "\n") {
		if !strings.HasPrefix(line, "p") {
			continue
		}
		pid, err := strconv.Atoi(line[1:])
		if err != nil {
			continue
		}
		if pid == myPID {
			continue
		}
		if pid > 0 {
			return pid
		}
	}
	return 0
}
