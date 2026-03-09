//go:build linux

package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// verifyPeerUID checks that the connecting process has the same UID as the daemon.
// Uses SO_PEERCRED on Linux.
func verifyPeerUID(conn net.Conn, expectedUID uint32) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return fmt.Errorf("raw control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("getsockopt SO_PEERCRED: %w", credErr)
	}
	if cred.Uid != expectedUID {
		return fmt.Errorf("peer UID %d does not match expected UID %d", cred.Uid, expectedUID)
	}
	return nil
}
