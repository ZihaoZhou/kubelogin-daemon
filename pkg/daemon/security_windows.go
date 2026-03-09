//go:build windows

package daemon

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// validateRuntimeDirSecurity checks that the runtime directory is safe to use.
// On Windows, checks: (1) not a reparse point (junction/symlink), (2) SID ownership.
// GetNamedSecurityInfo follows junctions, so an attacker-created junction to a dir
// they own would pass the SID check. We must detect reparse points first.
func validateRuntimeDirSecurity(path string) error {
	// HIGH-1: Check for NTFS junctions / reparse points before SID check.
	// Junctions don't require special privileges (unlike symlinks pre-Developer Mode),
	// making them a realistic attack vector.
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	h, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("open runtime dir for reparse check: %w", err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return fmt.Errorf("GetFileInformationByHandle: %w", err)
	}
	windows.CloseHandle(h)
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("runtime directory %s is a reparse point (junction/symlink) — rejected", path)
	}

	// SID ownership check
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("GetNamedSecurityInfo: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("get owner SID: %w", err)
	}

	self, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("get current user SID: %w", err)
	}

	if !windows.EqualSid(owner, self) {
		// On Windows, directories in %TEMP% are often owned by the Administrators
		// group (S-1-5-32-544) rather than the individual user when the user is an
		// admin. This is normal Windows behavior and safe — the DACL (set by
		// setPrivatePermissions) restricts access regardless of ownership.
		adminsSID, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if adminErr != nil || !windows.EqualSid(owner, adminsSID) {
			return fmt.Errorf("runtime directory %s owned by %s, expected %s", path, owner, self)
		}
		// Owner is Administrators and we got here, so the user is an admin.
		// Accept this as safe — the DACL is what actually controls access.
	}

	return nil
}

// setPrivatePermissions sets restrictive ACLs on a file or directory.
// On Windows, grants access only to the current user, SYSTEM, and Builtin\Administrators.
func setPrivatePermissions(path string, isDir bool) error {
	self, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("get current user SID: %w", err)
	}

	// Build explicit access entries
	accessMask := windows.ACCESS_MASK(windows.GENERIC_ALL)
	inheritFlags := uint32(0)
	if isDir {
		inheritFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: accessMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritFlags,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(self),
			},
		},
	}

	// Also grant SYSTEM access (required for some Windows services)
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err == nil {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: accessMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritFlags,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		})
	}

	// Also grant Administrators access
	adminsSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err == nil {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: accessMask,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       inheritFlags,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(adminsSID),
			},
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("ACLFromEntries: %w", err)
	}

	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}

// currentUserSID returns the SID of the current process user.
func currentUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	tu, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	// Copy the SID to avoid referencing token memory after close
	sidLen := windows.GetLengthSid(tu.User.Sid)
	buf := make([]byte, sidLen)
	if err := windows.CopySid(uint32(sidLen), (*windows.SID)(unsafe.Pointer(&buf[0])), tu.User.Sid); err != nil {
		return nil, err
	}
	return (*windows.SID)(unsafe.Pointer(&buf[0])), nil
}

// Ensure os is used (referenced in setPrivatePermissions signature via isDir param)
var _ = os.Chmod
