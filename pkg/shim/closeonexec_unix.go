//go:build !windows

package shim

import "syscall"

// setCloseOnExecAboveStderr sets FD_CLOEXEC on all file descriptors > 2.
// This ensures the forked daemon child does not inherit non-Go fds from
// the parent process (e.g., flock locks from kubectl wrappers, leaked
// sockets). CLOEXEC fds are atomically closed by the kernel during exec,
// so the parent's own fds remain usable.
//
// Must be called just before cmd.Start() — after constructing the Command
// but before fork+exec happens.
func setCloseOnExecAboveStderr() {
	var rlim syscall.Rlimit
	maxFd := 1024
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		maxFd = int(rlim.Cur)
	}
	if maxFd > 65536 {
		maxFd = 65536 // sanity cap for pathological RLIMIT_NOFILE values
	}
	for fd := 3; fd < maxFd; fd++ {
		syscall.CloseOnExec(fd)
	}
}
