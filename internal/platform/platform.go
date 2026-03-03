// Package platform provides OS-specific abstractions for IPC listeners,
// process identification, biometric prompts, and TPM key sealing.
package platform

import "net"

// Platform abstracts OS-specific capabilities needed for app access control.
type Platform interface {
	// Listener returns a net.Listener bound to the platform-appropriate IPC
	// mechanism (named pipe on Windows, Unix socket on Linux/macOS).
	Listener(path string) (net.Listener, error)

	// PeerPID returns the process ID of the peer connected on conn.
	// The conn must originate from a platform Listener.
	PeerPID(conn net.Conn) (int, error)

	// ProcessPath returns the full executable path for the given PID.
	ProcessPath(pid int) (string, error)

	// BiometricPrompt requests human verification via platform biometric
	// (Windows Hello, Touch ID, FIDO2/polkit). The reason string is shown
	// in the system prompt. Returns nil on success, error on denial/timeout.
	BiometricPrompt(reason string) error

	// HasBiometric reports whether the platform has a usable biometric mechanism.
	HasBiometric() bool
}
