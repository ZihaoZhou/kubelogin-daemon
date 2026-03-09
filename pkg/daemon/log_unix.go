//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// SEC-HIGH-2: openLogFileNoFollow wraps os.OpenFile with O_NOFOLLOW to
// atomically reject symlinks, closing the TOCTOU gap between Lstat and Open.
func openLogFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW, perm)
}
