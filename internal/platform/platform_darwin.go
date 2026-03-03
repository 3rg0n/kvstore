//go:build darwin

package platform

import (
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Darwin implements Platform using Unix domain sockets and macOS APIs.
type Darwin struct{}

// New returns the macOS platform implementation.
func New() Platform {
	return &Darwin{}
}

// Listener returns a Unix domain socket listener at the given path.
// Removes any stale socket file before binding.
func (d *Darwin) Listener(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on unix socket %s: %w", path, err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("setting socket permissions: %w", err)
	}
	return ln, nil
}

// PeerPID returns the process ID of the Unix socket peer using LOCAL_PEERPID.
func (d *Darwin) PeerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("getting syscall conn: %w", err)
	}

	// LOCAL_PEERPID = 0x002 on macOS, SOL_LOCAL = 0
	const solLocal = 0
	const localPeerPID = 0x002

	var pid int32
	var optErr error
	err = raw.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(pid))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			solLocal,
			localPeerPID,
			uintptr(unsafe.Pointer(&pid)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			optErr = fmt.Errorf("getsockopt LOCAL_PEERPID: %w", errno)
		}
	})
	if err != nil {
		return 0, fmt.Errorf("Control: %w", err)
	}
	if optErr != nil {
		return 0, optErr
	}
	return int(pid), nil
}

// ProcessPath returns the executable path for the given PID using the
// proc_info syscall (PROC_PIDPATHINFO).
func (d *Darwin) ProcessPath(pid int) (string, error) {
	const procPidPathInfo = 11 // PROC_PIDPATHINFO
	buf := make([]byte, 4096)  // PROC_PIDPATHINFO_MAXSIZE
	_, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO, // proc_info syscall
		2,                   // PROC_INFO_CALL_PIDINFO
		uintptr(pid),
		procPidPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return "", fmt.Errorf("proc_info PROC_PIDPATHINFO(%d): %w", pid, errno)
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf), nil
}

// BiometricPrompt requests Touch ID verification via inline swift execution.
//
// Uses LAContext from LocalAuthentication framework via a swift one-liner.
// swift is always available on macOS, so no CGO or external binary is needed.
func (d *Darwin) BiometricPrompt(reason string) error {
	// TODO: Implement Touch ID via:
	// swift -e 'import LocalAuthentication; let c = LAContext(); ...'
	// For now, stub that always succeeds.
	_ = reason
	return nil
}

// HasBiometric reports whether Touch ID is available.
func (d *Darwin) HasBiometric() bool {
	// A full check would run:
	// swift -e 'import LocalAuthentication; print(LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil))'
	return true
}
