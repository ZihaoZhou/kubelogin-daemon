//go:build windows

package shim

// setCloseOnExecAboveStderr is a no-op on Windows.
// Windows handle inheritance is prevented by NoInheritHandles in
// SysProcAttr (see procattr_windows.go).
func setCloseOnExecAboveStderr() {}
