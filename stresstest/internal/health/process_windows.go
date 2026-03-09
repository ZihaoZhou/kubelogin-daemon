//go:build windows

package health

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// processExists checks if a process with the given PID is alive.
func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows, FindProcess always succeeds for valid PIDs.
	// Use tasklist to verify the process is actually running.
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		_ = proc
		return false
	}
	return strings.Contains(string(out), strconv.Itoa(pid))
}

// getProcessRSS returns the working set size in bytes for the given PID.
func getProcessRSS(pid int) (int64, error) {
	// Use tasklist /FI to get memory usage for a specific PID.
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return 0, fmt.Errorf("tasklist: %w", err)
	}

	// Output format: "process.exe","PID","Session Name","Session#","Mem Usage"
	// Mem Usage is like "12,345 K"
	line := strings.TrimSpace(string(out))
	if line == "" || strings.Contains(line, "No tasks") {
		return 0, fmt.Errorf("process %d not found", pid)
	}

	fields := strings.Split(line, "\",\"")
	if len(fields) < 5 {
		return 0, fmt.Errorf("unexpected tasklist output: %s", line)
	}

	// Last field is like: 12,345 K"
	memStr := fields[4]
	memStr = strings.TrimSuffix(memStr, "\"")
	memStr = strings.TrimSpace(memStr)
	memStr = strings.TrimSuffix(memStr, "K")
	memStr = strings.TrimSpace(memStr)
	memStr = strings.ReplaceAll(memStr, ",", "")

	kb, err := strconv.ParseInt(memStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse memory %q: %w", memStr, err)
	}

	return kb * 1024, nil
}
