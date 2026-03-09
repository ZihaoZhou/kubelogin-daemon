//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// findPIDBySocket finds the PID of a running kubelogin-daemon process on Windows.
// Since named pipes are kernel-managed (no inode), we enumerate all processes via
// CreateToolhelp32Snapshot and look for "kubelogin-daemon.exe", skipping our own PID.
func findPIDBySocket(socketPath string) int {
	const (
		TH32CS_SNAPPROCESS = 0x00000002
		MAX_PATH           = 260
	)

	type processEntry32 struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriorityClassBase int32
		Flags             uint32
		ExeFile           [MAX_PATH]uint16
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirst := kernel32.NewProc("Process32FirstW")
	processNext := kernel32.NewProc("Process32NextW")

	handle, _, _ := createSnapshot.Call(TH32CS_SNAPPROCESS, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return 0
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	myPID := uint32(os.Getpid())
	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := processFirst.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if name == "kubelogin-daemon.exe" && entry.ProcessID != myPID {
			return int(entry.ProcessID)
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = processNext.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return 0
}
