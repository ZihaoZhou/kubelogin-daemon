//go:build !windows

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

func transportAddress(runtimeDir string) string {
	return filepath.Join(runtimeDir, "sock")
}

func transportListen(address string) (net.Listener, uint64, error) {
	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, 0, err
	}
	// Disable Go's automatic socket file removal on Close().
	// net.UnixListener.Close() calls syscall.Unlink(path), which removes
	// whatever file currently exists at that path — even if another daemon
	// replaced the socket. We handle removal in TransportCleanup with
	// an inode check.
	if unixL, ok := listener.(*net.UnixListener); ok {
		unixL.SetUnlinkOnClose(false)
	}

	var inode uint64
	if info, err := os.Stat(address); err == nil {
		inode = fileInode(info)
	}
	return listener, inode, nil
}

func transportDial(address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", address, timeout)
}

func transportCleanup(address string, expectedInode uint64) {
	info, err := os.Stat(address)
	if err != nil {
		return // already gone
	}
	if expectedInode == 0 || fileInode(info) == expectedInode {
		os.Remove(address)
	}
}
