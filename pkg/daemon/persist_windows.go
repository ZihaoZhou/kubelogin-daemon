//go:build windows

package daemon

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// runtimeUserID returns a stable per-user identifier for the runtime directory name.
// On Windows, this is the SID string (e.g., "S-1-5-21-...-1001").
func runtimeUserID() string {
	token := windows.GetCurrentProcessToken()
	tu, err := token.GetTokenUser()
	if err != nil {
		// Fallback: use "0" (same as before, but shouldn't happen)
		return "0"
	}
	return tu.User.Sid.String()
}

// stableTempDir returns a stable temp directory for the runtime dir.
// On Windows, %TEMP% is per-user and stable across sessions (unlike macOS TMPDIR).
func stableTempDir() string {
	return os.TempDir()
}

// openNoFollow opens a file, atomically rejecting symlinks.
// SEC-HIGH-1: The previous Lstat→Open approach had a TOCTOU gap exploitable
// when Developer Mode is enabled (which removes the SeCreateSymbolicLinkPrivilege
// requirement, letting ordinary users create symlinks).
//
// Fix: Open with FILE_FLAG_OPEN_REPARSE_POINT (which opens the reparse point
// itself rather than following it), then check FILE_ATTRIBUTE_REPARSE_POINT on
// the same handle. No window between check and use.
func openNoFollow(path string) (*os.File, error) {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}
	h, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, os.NewSyscallError("CreateFile", err)
	}
	// Check if the opened handle is a reparse point (symlink/junction).
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, os.NewSyscallError("GetFileInformationByHandle", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("persist file is a symlink (rejected)")
	}
	return os.NewFile(uintptr(h), path), nil
}

// platformUID returns a UID for peer verification.
// COMPAT-10: On Windows, os.Getuid() returns -1 (uint32 max). Since
// verifyPeerUID is a no-op on Windows (SEC-4: relies on ACL defense
// via setPrivatePermissions), we return 0 as a safe sentinel.
func platformUID() uint32 {
	return 0
}

// fileInode returns a file identifier from its os.FileInfo.
// B2: On Windows there are no inodes. Return 0 and rely on path-based
// socket existence check (os.Stat) in idleWatcher instead.
func fileInode(info os.FileInfo) uint64 {
	return 0
}
