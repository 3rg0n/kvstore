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
	return processPathDarwin(pid)
}

func processPathDarwin(pid int) (string, error) {
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

// ResolveBinary atomically resolves a connection to the caller's PID and
// binary path. On macOS, uses LOCAL_PEERPID + proc_info PROC_PIDPATHINFO
// back-to-back. While macOS doesn't offer a kernel-level inode guarantee
// like Linux's /proc/PID/exe, the proc_info syscall queries the kernel's
// process table directly — more robust than a filesystem path lookup.
func (d *Darwin) ResolveBinary(conn net.Conn) (int, string, error) {
	pid, err := d.PeerPID(conn)
	if err != nil {
		return 0, "", fmt.Errorf("resolving peer PID: %w", err)
	}

	path, err := processPathDarwin(pid)
	if err != nil {
		return 0, "", fmt.Errorf("resolving binary path for PID %d: %w", pid, err)
	}
	return pid, path, nil
}

// BiometricPrompt requests Touch ID verification via LocalAuthentication.framework.
// Blocks until the user verifies with Touch ID or cancels.
func (d *Darwin) BiometricPrompt(reason string) error {
	return touchIDPrompt(reason)
}

// HasBiometric reports whether Touch ID hardware is present and enrolled.
func (d *Darwin) HasBiometric() bool {
	return touchIDAvailable()
}

// TPMSeal seals data using the macOS Secure Enclave.
// A P-256 key is created in the Secure Enclave on first use and stored
// in the Keychain. Data is encrypted with ECIES; the private key never
// leaves the hardware.
func (d *Darwin) TPMSeal(data []byte) ([]byte, error) {
	return enclaveSeal(data)
}

// TPMUnseal reverses a TPMSeal operation using the Secure Enclave.
func (d *Darwin) TPMUnseal(sealed []byte) ([]byte, error) {
	return enclaveUnseal(sealed)
}

// HasTPM reports whether the Secure Enclave is available (T2 or Apple Silicon).
func (d *Darwin) HasTPM() bool {
	return enclaveAvailable()
}
