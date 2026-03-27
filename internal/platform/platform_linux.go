//go:build linux

package platform

import (
	"fmt"
	"net"
	"os"
	"os/exec"

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

// ResolveBinary atomically resolves a connection to the caller's PID and
// binary path. On Linux, reads /proc/PID/exe which is a kernel-maintained
// symlink to the inode of the running process — immune to path swaps.
func (l *Linux) ResolveBinary(conn net.Conn) (int, string, error) {
	pid, err := l.PeerPID(conn)
	if err != nil {
		return 0, "", fmt.Errorf("resolving peer PID: %w", err)
	}

	// Read /proc/PID/exe — this reads the kernel's cached inode, not the
	// filesystem path. Even if the binary is swapped on disk, this returns
	// the path of the binary that was exec'd for this PID.
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, "", fmt.Errorf("reading /proc/%d/exe: %w", pid, err)
	}
	return pid, path, nil
}

// BiometricPrompt requests user verification via fprintd (fingerprint daemon).
// Uses the fprintd-verify D-Bus service which is standard on most Linux desktops
// with fingerprint hardware. Returns an error if verification fails or fprintd
// is not available.
func (l *Linux) BiometricPrompt(_ string) error {
	cmd := exec.Command("fprintd-verify")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fingerprint verification failed: %s", string(output))
	}
	return nil
}

// HasBiometric reports whether fprintd fingerprint verification is available.
func (l *Linux) HasBiometric() bool {
	_, err := exec.LookPath("fprintd-verify")
	return err == nil
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
