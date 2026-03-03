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
}
