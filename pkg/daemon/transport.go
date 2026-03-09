package daemon

import (
	"net"
	"time"
)

// Transport abstracts the platform-specific IPC mechanism.
// Unix: Unix domain socket. Windows: named pipe.
//
// All functions are implemented in transport_unix.go and transport_windows.go.

// TransportAddress returns the platform-specific IPC address.
// Unix: runtimeDir/sock (filesystem path)
// Windows: \\.\pipe\kubelogin-daemon-<SID> (kernel namespace)
func TransportAddress(runtimeDir string) string {
	return transportAddress(runtimeDir)
}

// TransportListen creates a platform-specific listener.
// Returns the listener and the socket inode (0 on Windows).
func TransportListen(address string) (net.Listener, uint64, error) {
	return transportListen(address)
}

// TransportDial connects to the daemon using the platform-specific transport.
func TransportDial(address string, timeout time.Duration) (net.Conn, error) {
	return transportDial(address, timeout)
}

// TransportCleanup removes IPC artifacts on shutdown.
// Unix: stat + inode check + os.Remove.
// Windows: no-op (named pipes are kernel-managed).
func TransportCleanup(address string, expectedInode uint64) {
	transportCleanup(address, expectedInode)
}

// TransportProbeAlive checks if a daemon is listening at the given address.
func TransportProbeAlive(address string, timeout time.Duration) bool {
	conn, err := TransportDial(address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
