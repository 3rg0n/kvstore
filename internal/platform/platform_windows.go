//go:build windows

package platform

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows implements Platform using named pipes and Win32 APIs.
type Windows struct{}

// New returns the Windows platform implementation.
func New() Platform {
	return &Windows{}
}

// Listener returns a named pipe listener. The path should be a pipe name
// like "kvstore" which becomes \\.\pipe\kvstore.
//
// Go's net package doesn't natively support named pipes. A production
// implementation would use microsoft/go-winio. For now we use a localhost
// TCP listener as a functional stub. PeerPID will attempt
// GetNamedPipeClientProcessId and gracefully fail for TCP connections.
func (w *Windows) Listener(_ string) (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

var (
	modkernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = modkernel32.NewProc("GetNamedPipeClientProcessId")
	procQueryFullProcessImageNameW  = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// PeerPID returns the process ID of the named pipe client.
// For TCP connections (stub), this returns an error.
func (w *Windows) PeerPID(conn net.Conn) (int, error) {
	sc, ok := conn.(interface {
		SyscallConn() (interface {
			Control(func(fd uintptr)) error
		}, error)
	})
	if !ok {
		return 0, fmt.Errorf("connection does not support SyscallConn")
	}

	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("getting syscall conn: %w", err)
	}

	var pid uint32
	var callErr error
	err = raw.Control(func(fd uintptr) {
		r1, _, e := procGetNamedPipeClientProcessId.Call(fd, uintptr(unsafe.Pointer(&pid))) //nolint:gosec // Win32 syscall requires unsafe
		if r1 == 0 {
			callErr = fmt.Errorf("GetNamedPipeClientProcessId: %w", e)
		}
	})
	if err != nil {
		return 0, err
	}
	if callErr != nil {
		return 0, callErr
	}
	return int(pid), nil
}

// ProcessPath returns the full executable path for the given PID using
// QueryFullProcessImageNameW.
func (w *Windows) ProcessPath(pid int) (string, error) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		uint32(pid), //nolint:gosec // PID always fits in uint32
	)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf)) //nolint:gosec // MAX_PATH fits in uint32
	r1, _, e := procQueryFullProcessImageNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])), //nolint:gosec // Win32 syscall requires unsafe
		uintptr(unsafe.Pointer(&size)),   //nolint:gosec // Win32 syscall requires unsafe
	)
	if r1 == 0 {
		return "", fmt.Errorf("QueryFullProcessImageNameW: %w", e)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// BiometricPrompt requests Windows Hello verification.
//
// A full implementation would use webauthn.dll (via go-ctap/winhello) to
// trigger the Windows Hello dialog. For now this is a stub that always
// succeeds — real biometric gating will be wired when the winhello
// dependency is integrated.
func (w *Windows) BiometricPrompt(_ string) error {
	// TODO: Integrate go-ctap/winhello for Windows Hello prompt
	return nil
}

// HasBiometric reports whether Windows Hello is available.
func (w *Windows) HasBiometric() bool {
	// Windows Hello availability check via webauthn.dll
	// Stub: assume available on Windows 10+
	return true
}

// TPMSeal seals data to this machine's TPM 2.0 via Windows TBS.
// The data is bound to the TPM's Storage Root Key and cannot be
// unsealed on a different machine.
func (w *Windows) TPMSeal(data []byte) ([]byte, error) {
	return tpmSeal(data)
}

// TPMUnseal recovers data sealed by TPMSeal.
func (w *Windows) TPMUnseal(sealed []byte) ([]byte, error) {
	return tpmUnseal(sealed)
}

// HasTPM reports whether TPM 2.0 is available via Windows TBS.
func (w *Windows) HasTPM() bool {
	return tpmAvailable()
}
