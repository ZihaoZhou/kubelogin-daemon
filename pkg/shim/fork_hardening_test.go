//go:build !windows

package shim

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestSetCloseOnExecAboveStderr_DoesNotPanic verifies that the CLOEXEC
// function can be called safely without panicking or breaking the process.
func TestSetCloseOnExecAboveStderr_DoesNotPanic(t *testing.T) {
	// Simply calling it should not panic or error.
	setCloseOnExecAboveStderr()

	// The calling process should still function normally.
	// Verify by opening a file (proves fd allocation still works).
	f, err := os.CreateTemp(t.TempDir(), "cloexec-test")
	if err != nil {
		t.Fatalf("os.CreateTemp after setCloseOnExecAboveStderr: %v", err)
	}
	f.Close()
}

// TestSetCloseOnExecAboveStderr_FdStillUsable verifies that fds remain
// usable in the current process after CLOEXEC is set (CLOEXEC only
// affects exec, not current process operations).
func TestSetCloseOnExecAboveStderr_FdStillUsable(t *testing.T) {
	// Open a file to get an fd > 2.
	f, err := os.CreateTemp(t.TempDir(), "cloexec-test")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()

	// Set CLOEXEC on all fds > 2 (including our test fd).
	setCloseOnExecAboveStderr()

	// The fd should still be writable (CLOEXEC doesn't affect current process).
	if _, err := f.WriteString("test data"); err != nil {
		t.Errorf("Write after setCloseOnExecAboveStderr failed: %v", err)
	}
}

// TestSetCloseOnExecAboveStderr_SetsCloexecFlag verifies that the function
// actually sets the FD_CLOEXEC flag on open file descriptors.
func TestSetCloseOnExecAboveStderr_SetsCloexecFlag(t *testing.T) {
	// Create a pipe to get an fd without CLOEXEC.
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	// Verify pipe fds don't have CLOEXEC initially.
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fds[0]), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("fcntl F_GETFD: %v", errno)
	}
	if flags&syscall.FD_CLOEXEC != 0 {
		t.Skip("pipe fd already has CLOEXEC (platform default), can't test setting it")
	}

	// Set CLOEXEC on all fds > 2.
	setCloseOnExecAboveStderr()

	// Verify CLOEXEC is now set on the pipe fd.
	flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fds[0]), uintptr(syscall.F_GETFD), 0)
	if errno != 0 {
		t.Fatalf("fcntl F_GETFD after setCloseOnExec: %v", errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Errorf("fd %d should have FD_CLOEXEC set after setCloseOnExecAboveStderr", fds[0])
	}
}

// TestSanitizedEnv_WhitelistOnly verifies that sanitizedEnv only includes
// whitelisted variables.
func TestSanitizedEnv_WhitelistOnly(t *testing.T) {
	// Set a whitelisted var and a non-whitelisted var.
	t.Setenv("HOME", "/test/home")
	t.Setenv("KUBECONFIG", "/should/not/appear")
	t.Setenv("LD_PRELOAD", "/evil/lib.so")
	t.Setenv("GODEBUG", "tracealloc=1")

	env := sanitizedEnv()

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// HOME should be present.
	if val, ok := envMap["HOME"]; !ok || val != "/test/home" {
		t.Errorf("HOME should be /test/home, got %q (present=%v)", val, ok)
	}

	// Dangerous vars should NOT be present.
	for _, key := range []string{"KUBECONFIG", "LD_PRELOAD", "GODEBUG"} {
		if _, ok := envMap[key]; ok {
			t.Errorf("%s should NOT be in sanitized env", key)
		}
	}
}

// TestSanitizedEnv_ReturnsEmptySliceNotNil verifies that sanitizedEnv
// returns an empty slice (not nil) when no whitelisted vars are set.
// This is critical because cmd.Env = nil means "inherit all".
func TestSanitizedEnv_ReturnsEmptySliceNotNil(t *testing.T) {
	// Unset all whitelisted vars.
	for _, key := range envWhitelist {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	env := sanitizedEnv()

	if env == nil {
		t.Fatal("sanitizedEnv() returned nil — this would cause cmd.Env=nil which inherits all parent env!")
	}
	// Should be a non-nil empty (or near-empty) slice.
	// Note: some vars may be impossible to fully unset in test harness,
	// so we just check non-nil.
}

// TestSanitizedEnv_ProxyVarsCaseSensitive verifies both uppercase and
// lowercase proxy variables are whitelisted.
func TestSanitizedEnv_ProxyVarsCaseSensitive(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy:8080")
	t.Setenv("https_proxy", "http://proxy:8080")
	t.Setenv("NO_PROXY", "localhost")
	t.Setenv("no_proxy", "localhost")

	env := sanitizedEnv()
	envSet := make(map[string]bool)
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		envSet[key] = true
	}

	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if !envSet[key] {
			t.Errorf("%s should be in sanitized env (Go net/http checks both cases)", key)
		}
	}
}
