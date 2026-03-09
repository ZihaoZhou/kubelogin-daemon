//go:build windows

package daemon

import (
	"net"
)

// verifyPeerUID is a no-op on Windows.
//
// SEC-4: Windows uses named pipes with kernel-enforced SDDL ACLs
// (see transport_windows.go userOnlySDDL). The pipe's security descriptor
// restricts access to the current user and SYSTEM, providing equivalent
// protection to Unix SO_PEERCRED without needing per-connection checks.
//
// The SEC-9 nonce-based mutual authentication provides an additional
// layer of defense on all platforms including Windows.
func verifyPeerUID(conn net.Conn, expectedUID uint32) error {
	return nil
}
