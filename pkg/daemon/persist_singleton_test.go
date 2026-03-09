//go:build !windows

package daemon

import (
	"os"
	"testing"
)

// These tests expose the RuntimeDir TMPDIR fragility bug.
// The singleton pattern requires RuntimeDir to be STABLE — the daemon
// and get-token MUST agree on the socket path regardless of environment.
// Currently, RuntimeDir uses os.TempDir() which reads $TMPDIR, so any
// environment change (scripts, build systems, cron, docker) breaks singleton.

func TestRuntimeDir_Immune_To_TMPDIR(t *testing.T) {
	// RuntimeDir must return the same path regardless of TMPDIR value.
	// This is the core singleton invariant: daemon and get-token must
	// agree on the socket path even when TMPDIR differs between processes.
	//
	// Real-world failures:
	// - Scripts: TMPDIR=$(mktemp -d) ... kubectl get pods
	// - Docker: TMPDIR=/tmp/docker-xxx
	// - Build systems: TMPDIR=/build/tmp make deploy
	// - Cron: TMPDIR not set at all

	originalTMPDIR := os.Getenv("TMPDIR")
	defer func() {
		if originalTMPDIR != "" {
			os.Setenv("TMPDIR", originalTMPDIR)
		} else {
			os.Unsetenv("TMPDIR")
		}
	}()

	baseline := RuntimeDir()

	// Simulate a script that overrides TMPDIR (e.g., TMPDIR=$(mktemp -d))
	os.Setenv("TMPDIR", "/tmp/altered-by-script")
	altered := RuntimeDir()

	if baseline != altered {
		t.Errorf("RuntimeDir is fragile to TMPDIR changes!\n"+
			"  TMPDIR=%q → RuntimeDir=%q\n"+
			"  TMPDIR=%q → RuntimeDir=%q\n"+
			"This breaks singleton: daemon and get-token use different sockets.\n"+
			"100 concurrent kubectl calls ALL got NEEDS_LOGIN because each\n"+
			"auto-started a new daemon in the wrong directory.",
			originalTMPDIR, baseline,
			"/tmp/altered-by-script", altered)
	}
}

func TestRuntimeDir_Immune_To_TMPDIR_Unset(t *testing.T) {
	// When TMPDIR is unset (common in cron, systemd, minimal containers),
	// RuntimeDir must still return the same path as when TMPDIR is set.

	originalTMPDIR := os.Getenv("TMPDIR")
	defer func() {
		if originalTMPDIR != "" {
			os.Setenv("TMPDIR", originalTMPDIR)
		} else {
			os.Unsetenv("TMPDIR")
		}
	}()

	// Skip if TMPDIR is not set (nothing to test — both paths would be /tmp)
	if originalTMPDIR == "" {
		t.Skip("TMPDIR not set; divergence test not applicable")
	}

	baseline := RuntimeDir()

	// Simulate cron/systemd environment where TMPDIR is not set
	os.Unsetenv("TMPDIR")
	unsetDir := RuntimeDir()

	if baseline != unsetDir {
		t.Errorf("RuntimeDir changes when TMPDIR is unset!\n"+
			"  TMPDIR=%q → RuntimeDir=%q\n"+
			"  TMPDIR=<unset>  → RuntimeDir=%q\n"+
			"Daemon started in interactive shell won't be found by cron-invoked kubectl.",
			originalTMPDIR, baseline,
			unsetDir)
	}
}

func TestRuntimeDir_UsesFixedPath(t *testing.T) {
	// RuntimeDir should use a well-known fixed path (/tmp/kubelogin-daemon-UID)
	// regardless of TMPDIR, just like gpg-agent and ssh-agent do.
	// Only XDG_RUNTIME_DIR (if set) should override it.

	originalTMPDIR := os.Getenv("TMPDIR")
	originalXDG := os.Getenv("XDG_RUNTIME_DIR")
	defer func() {
		if originalTMPDIR != "" {
			os.Setenv("TMPDIR", originalTMPDIR)
		} else {
			os.Unsetenv("TMPDIR")
		}
		if originalXDG != "" {
			os.Setenv("XDG_RUNTIME_DIR", originalXDG)
		} else {
			os.Unsetenv("XDG_RUNTIME_DIR")
		}
	}()

	// Unset XDG_RUNTIME_DIR so we test the fallback path
	os.Unsetenv("XDG_RUNTIME_DIR")

	// Try multiple TMPDIR values — RuntimeDir must be the same for all
	tmpdirs := []string{
		"/var/folders/dr/zc93rzys17n0g206csz8fdt40000gn/T/", // macOS default
		"/tmp",                   // Linux default / TMPDIR unset
		"/tmp/altered-by-script", // script override
		"/build/tmp",             // build system
		"",                       // unset
	}

	var results []string
	for _, td := range tmpdirs {
		if td == "" {
			os.Unsetenv("TMPDIR")
		} else {
			os.Setenv("TMPDIR", td)
		}
		results = append(results, RuntimeDir())
	}

	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("RuntimeDir is NOT fixed:\n"+
				"  TMPDIR=%q → %q\n"+
				"  TMPDIR=%q → %q\n"+
				"Should be the same path regardless of TMPDIR.",
				tmpdirs[0], first,
				tmpdirs[i], r)
		}
	}
}
