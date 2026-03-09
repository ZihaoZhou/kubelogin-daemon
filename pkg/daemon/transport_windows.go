//go:build windows

package daemon

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const pipePrefix = `\\.\pipe\kubelogin-daemon-`

func transportAddress(runtimeDir string) string {
	// Named pipe name based on user SID. This is deterministic — both
	// the daemon and shim derive the same pipe name independently.
	sid, err := currentUserSIDString()
	if err != nil {
		// Fallback to runtime dir based name if SID lookup fails.
		// This should never happen in practice.
		return pipePrefix + "default"
	}
	return pipePrefix + sid
}

func transportListen(address string) (net.Listener, uint64, error) {
	// Create named pipe with user-only ACL.
	// The SDDL grants Generic All to the current user and SYSTEM only.
	sddl, err := userOnlySDDL()
	if err != nil {
		return nil, 0, fmt.Errorf("build pipe SDDL: %w", err)
	}

	cfg := &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	}

	listener, err := winio.ListenPipe(address, cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("bind pipe %s: %w", address, err)
	}
	// Inode is meaningless for named pipes — return 0.
	return listener, 0, nil
}

func transportDial(address string, timeout time.Duration) (net.Conn, error) {
	return winio.DialPipe(address, &timeout)
}

func transportCleanup(address string, expectedInode uint64) {
	// No-op. Named pipes are kernel-managed and destroyed when the last
	// handle closes. No filesystem artifacts to clean up.
}

// userOnlySDDL returns an SDDL string granting access only to the current
// user and SYSTEM. This is the primary security mechanism for named pipes
// on Windows — kernel-enforced, unlike file permissions.
func userOnlySDDL() (string, error) {
	sid, err := currentUserSIDString()
	if err != nil {
		return "", err
	}
	// D: DACL
	// (A;;GA;;;SID) — Allow Generic All to current user
	// (A;;GA;;;SY)  — Allow Generic All to SYSTEM
	return fmt.Sprintf("D:(A;;GA;;;%s)(A;;GA;;;SY)", sid), nil
}

// currentUserSIDString returns the string representation of the current
// user's SID (e.g., "S-1-5-21-...").
func currentUserSIDString() (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}
