//go:build windows

package daemon

// disableCoreDump is a no-op on Windows.
// Windows doesn't use core dumps in the same way.
func disableCoreDump() {}
