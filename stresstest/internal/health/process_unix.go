//go:build !windows

package health

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// processExists checks if a process with the given PID is alive.
func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Use Signal(0) to check.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// getProcessRSS returns the RSS in bytes for the given PID.
func getProcessRSS(pid int) (int64, error) {
	switch runtime.GOOS {
	case "linux":
		return getProcessRSSLinux(pid)
	case "darwin":
		return getProcessRSSDarwin(pid)
	default:
		return 0, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getProcessRSSLinux reads /proc/PID/statm and returns RSS in bytes.
func getProcessRSSLinux(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected statm format")
	}

	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}

	pageSize := int64(os.Getpagesize())
	return pages * pageSize, nil
}

// getProcessRSSDarwin uses ps to get RSS in KB, converts to bytes.
func getProcessRSSDarwin(pid int) (int64, error) {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, err
	}

	kb, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, err
	}

	return kb * 1024, nil // KB to bytes
}
