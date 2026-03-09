//go:build darwin

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// verifyPeerUID checks that the connecting process has the same UID as the daemon.
// Uses LOCAL_PEERCRED / getpeereid equivalent on macOS.
func verifyPeerUID(conn net.Conn, expectedUID uint32) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var peerUID uint32
	var credErr error
	err = raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			peerUID = cred.Uid
		}
	})
	if err != nil {
		return fmt.Errorf("raw control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("getsockopt LOCAL_PEERCRED: %w", credErr)
	}
	if peerUID != expectedUID {
		return fmt.Errorf("peer UID %d does not match expected UID %d", peerUID, expectedUID)
	}
	return nil
}
