package workload

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ZihaoZhou/kubelogin-daemon/stresstest/internal/logging"
)

// KubectlExecutor runs kubectl commands with timeout and failure classification.
type KubectlExecutor struct {
	namespace  string
	context    string
	timeout    time.Duration
	logger     *logging.Logger
}

// NewKubectlExecutor creates a new executor.
func NewKubectlExecutor(namespace, kubeContext string, timeout time.Duration, logger *logging.Logger) *KubectlExecutor {
	return &KubectlExecutor{
		namespace: namespace,
		context:   kubeContext,
		timeout:   timeout,
		logger:    logger,
	}
}

// Run executes a kubectl command and returns the result.
func (e *KubectlExecutor) Run(ctx context.Context, tmpl CmdTemplate, category CommandCategory, commandType string) CommandResult {
	args := make([]string, 0, len(tmpl.Args)+4)

	// Add namespace for namespace-scoped commands
	if e.namespace != "" && !isClusterScoped(tmpl.Args) {
		args = append(args, "--namespace", e.namespace)
	}

	// Add context if specified
	if e.context != "" {
		args = append(args, "--context", e.context)
	}

	args = append(args, tmpl.Args...)

	cmdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(cmdCtx, "kubectl", args...)

	if tmpl.Stdin != "" {
		cmd.Stdin = strings.NewReader(tmpl.Stdin)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := CommandResult{
		Timestamp:         start,
		Category:          category,
		CommandType:       commandType,
		Args:              args,
		Duration:          duration,
		ExpectClientError: tmpl.ExpectClientError,
	}

	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			result.FailureClass = FailTimeout
			result.ExitCode = -1
			result.Error = fmt.Sprintf("timeout after %s", e.timeout)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			result.Error = truncateStr(stderr.String(), 1024)
			result.FailureClass = classifyFailure(result.Error, result.ExitCode)
		} else {
			result.ExitCode = -1
			result.Error = err.Error()
			result.FailureClass = FailDaemonDown
		}
	}

	return result
}

// RunRaw executes kubectl with raw args and returns exit code + stderr.
func (e *KubectlExecutor) RunRaw(ctx context.Context, args []string) (int, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "kubectl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), stderr.String()
		}
		return -1, err.Error()
	}
	return 0, ""
}

// classifyFailure determines the failure class from stderr patterns.
func classifyFailure(stderr string, exitCode int) FailureClass {
	s := strings.ToLower(stderr)

	// Daemon-level failures
	if strings.Contains(s, "connection refused") ||
		strings.Contains(s, "no such file or directory") ||
		strings.Contains(s, "unable to connect to the server") {
		return FailDaemonDown
	}

	// Daemon returned an error (token not ready, internal error)
	if strings.Contains(s, "needs-auth") ||
		strings.Contains(s, "login-in-progress") ||
		strings.Contains(s, "daemon") {
		return FailDaemonError
	}

	// API server errors (5xx, timeouts)
	if strings.Contains(s, "internal error") ||
		strings.Contains(s, "503 service unavailable") ||
		strings.Contains(s, "500 internal server error") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "tls handshake timeout") {
		return FailAPIServer
	}

	// Client errors (RBAC, not found, bad input) — expected for some commands
	if strings.Contains(s, "forbidden") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "error:") ||
		strings.Contains(s, "unknown flag") ||
		strings.Contains(s, "invalid") ||
		strings.Contains(s, "the server doesn't have a resource type") {
		return FailClientError
	}

	// Default: if kubectl exited non-zero, treat as client error
	if exitCode != 0 {
		return FailClientError
	}

	return FailNone
}

func isClusterScoped(args []string) bool {
	if len(args) < 2 {
		return false
	}
	clusterResources := map[string]bool{
		"nodes": true, "namespaces": true, "clusterroles": true,
		"clusterrolebindings": true, "api-resources": true,
	}
	// Check verb + resource
	return clusterResources[args[1]]
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
