//go:build linux

package platform

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Linux implements Platform using Unix domain sockets and /proc.
type Linux struct{}

// New returns the Linux platform implementation.
func New() Platform {
	return &Linux{}
}

// Listener returns a Unix domain socket listener at the given path.
// Removes any stale socket file before binding.
func (l *Linux) Listener(path string) (net.Listener, error) {
	// Remove stale socket if it exists
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on unix socket %s: %w", path, err)
	}
	// Restrict socket permissions to owner only
	if err := os.Chmod(path, 0600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("setting socket permissions: %w", err)
	}
	return ln, nil
}

// PeerPID returns the process ID of the Unix socket peer using SO_PEERCRED.
func (l *Linux) PeerPID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("getting syscall conn: %w", err)
	}

	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // fd fits in int
	})
	if err != nil {
		return 0, fmt.Errorf("control: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("getsockoptUcred: %w", credErr)
	}
	return int(cred.Pid), nil
}

// ProcessPath returns the executable path for the given PID by reading
// /proc/{pid}/exe symlink.
func (l *Linux) ProcessPath(pid int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("reading /proc/%d/exe: %w", pid, err)
	}
	return path, nil
}

// BiometricPrompt requests user verification via polkit or FIDO2.
//
// A full implementation would use go-libfido2 for YubiKey or a polkit
// agent for desktop environments. For now this is a stub that always
// succeeds — real biometric gating will be wired when the FIDO2
// dependency is integrated.
func (l *Linux) BiometricPrompt(_ string) error {
	// TODO: Integrate go-libfido2 or polkit prompt
	return nil
}

// HasBiometric reports whether a biometric mechanism is available.
func (l *Linux) HasBiometric() bool {
	// Check for FIDO2 device or polkit agent
	// Stub: assume available
	return true
}

// TPMSeal seals data to this machine's TPM 2.0 via /dev/tpmrm0.
// The data is bound to the TPM's Storage Root Key and cannot be
// unsealed on a different machine.
func (l *Linux) TPMSeal(data []byte) ([]byte, error) {
	return tpmSeal(data)
}

// TPMUnseal recovers data sealed by TPMSeal.
func (l *Linux) TPMUnseal(sealed []byte) ([]byte, error) {
	return tpmUnseal(sealed)
}

// HasTPM reports whether TPM 2.0 is available via /dev/tpmrm0.
func (l *Linux) HasTPM() bool {
	return tpmAvailable()
}
