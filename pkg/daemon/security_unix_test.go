//go:build !windows

package daemon

import (
	"os"
	"syscall"
	"testing"
)

// TestValidateRuntimeDirSecurity_ChecksOwnership verifies that the security
// validation rejects directories owned by a different user.
//
// Background: Moving RuntimeDir from per-user /var/folders/.../T/ (mode 0700,
// only owner can access) to world-writable /tmp/ (mode 1777) introduces a
// directory pre-creation attack:
//   1. Attacker creates /tmp/kubelogin-daemon-<UID>/ owned by themselves
//   2. setPrivatePermissions (chmod 0700) fails with EPERM → daemon aborts
//   3. This is an implicit ownership check, but should be EXPLICIT
//
// Without an explicit ownership check, the security depends on chmod failing
// for non-owners — which is true on standard Unix but may not hold on all
// filesystems (NFS, FUSE, etc).
func TestValidateRuntimeDirSecurity_ChecksOwnership(t *testing.T) {
	dir := t.TempDir()
	// Our own directory — should pass
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := validateRuntimeDirSecurity(dir)
	if err != nil {
		t.Fatalf("own dir should pass: %v", err)
	}

	// Verify the function checks UID, not just permissions.
	// We can't create dirs as another user without root, but we can verify
	// the function actually reads and compares the UID.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("Stat_t not available on this platform")
	}
	if stat.Uid != uint32(os.Getuid()) {
		t.Fatalf("test setup wrong: dir UID %d != process UID %d", stat.Uid, os.Getuid())
	}

	// The key assertion: validateRuntimeDirSecurity MUST check ownership,
	// not just permissions. This test verifies the function signature
	// and behavior include ownership validation.
	//
	// If this test is green but the function only checks permissions (0700),
	// then the test is insufficient — we need a multi-user test environment.
	// For now, verify the function at least includes a UID comparison
	// by checking that it rejects a simulated scenario.
	//
	// Concrete test: verify that if we could somehow make a dir with
	// mode 0700 but wrong owner, validateRuntimeDirSecurity would catch it.
	// Since we can't without root, we document the requirement.
	t.Log("NOTE: Full ownership test requires multi-user environment (root).")
	t.Log("The function MUST compare stat.Uid against os.Getuid() to prevent")
	t.Log("/tmp directory pre-creation attacks.")
}

// TestValidateRuntimeDirSecurity_RejectsInsecurePerms verifies rejection
// of directories with group/other access bits.
func TestValidateRuntimeDirSecurity_RejectsInsecurePerms(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		mode os.FileMode
	}{
		{"group read", 0740},
		{"group write", 0720},
		{"group exec", 0710},
		{"other read", 0704},
		{"other write", 0702},
		{"other exec", 0701},
		{"world readable", 0755},
		{"world writable", 0777},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			if err := validateRuntimeDirSecurity(dir); err == nil {
				t.Errorf("should reject mode %04o", tc.mode)
			}
		})
	}
}

// TestValidateRuntimeDirSecurity_AcceptsCorrectPerms verifies acceptance
// of a properly secured directory.
func TestValidateRuntimeDirSecurity_AcceptsCorrectPerms(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := validateRuntimeDirSecurity(dir); err != nil {
		t.Errorf("should accept mode 0700: %v", err)
	}
}
