//go:build windows

package daemon

import "os"

// openLogFileNoFollow on Windows falls back to plain OpenFile.
// The Lstat check in the caller + runtime dir DACL provide defense-in-depth.
// (CreateFile with FILE_FLAG_OPEN_REPARSE_POINT would be ideal but is complex
// to combine with O_CREATE|O_TRUNC|O_APPEND disposition flags.)
func openLogFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}
