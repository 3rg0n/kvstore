//go:build windows

package platform

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
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
// The pipe is restricted to the creating user and SYSTEM via SDDL ACL.
// Note: FILE_FLAG_FIRST_PIPE_INSTANCE is not exposed by go-winio v0.6.2,
// but the SDDL (OW+SY only) provides equivalent protection against pipe
// name hijacking — only the owner or SYSTEM can create instances.
func (w *Windows) Listener(path string) (net.Listener, error) {
	pipePath := `\\.\pipe\` + path
	cfg := &winio.PipeConfig{
		// Owner (OW) and SYSTEM (SY) get full access; deny everyone else.
		// The P flag (PROTECTED) prevents inheritance of less restrictive ACLs.
		SecurityDescriptor: "D:P(A;;GA;;;OW)(A;;GA;;;SY)",
	}
	ln, err := winio.ListenPipe(pipePath, cfg)
	if err != nil {
		return nil, fmt.Errorf("listening on named pipe %s: %w", pipePath, err)
	}
	return ln, nil
}

var (
	modkernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procGetNamedPipeClientProcessId = modkernel32.NewProc("GetNamedPipeClientProcessId")
	procQueryFullProcessImageNameW  = modkernel32.NewProc("QueryFullProcessImageNameW")
)

// PeerPID returns the process ID of the named pipe client.
func (w *Windows) PeerPID(conn net.Conn) (int, error) {
	sc, ok := conn.(syscall.Conn)
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

	return queryProcessImageName(handle)
}

func queryProcessImageName(handle windows.Handle) (string, error) {
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

// ResolveBinary atomically resolves a connection to the caller's PID and
// binary path. On Windows, opens a process handle immediately after getting
// the PID and holds it while querying the image name. This prevents PID
// reuse attacks — if the original process exits and a new process takes its
// PID, the handle still refers to the original (now-terminated) process,
// and QueryFullProcessImageNameW will fail rather than return the wrong path.
func (w *Windows) ResolveBinary(conn net.Conn) (int, string, error) {
	// Step 1: Get the client PID from the named pipe handle
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0, "", fmt.Errorf("connection does not support SyscallConn")
	}

	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, "", fmt.Errorf("getting syscall conn: %w", err)
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
		return 0, "", err
	}
	if callErr != nil {
		return 0, "", callErr
	}

	// Step 2: Immediately open a handle to the process — this pins the
	// process object in the kernel. Even if the process exits and the PID
	// is reused, our handle still refers to the original process.
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return 0, "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	// Step 3: Query the image name using the pinned handle
	path, err := queryProcessImageName(handle)
	if err != nil {
		return 0, "", fmt.Errorf("resolving binary path for PID %d: %w", pid, err)
	}
	return int(pid), path, nil
}

// winRTPreamble is the PowerShell boilerplate for awaiting WinRT async calls.
// UserConsentVerifier lives in the Windows.Security.Credentials.UI namespace
// and provides the simplest path to trigger Windows Hello (fingerprint, face, PIN).
const winRTPreamble = `
[void][Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation` + "`" + `1'
})[0]
function Invoke-Async($op, $resultType) {
    $task = $asTaskGeneric.MakeGenericMethod($resultType).Invoke($null, @($op))
    $task.Wait() | Out-Null
    return $task.Result
}
`

// BiometricPrompt requests Windows Hello verification via UserConsentVerifier.
// Triggers the system Windows Hello dialog (fingerprint, face recognition, or PIN).
func (w *Windows) BiometricPrompt(reason string) error {
	script := winRTPreamble + `
$result = Invoke-Async ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:KVSTORE_BIO_REASON)) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
if ($result -ne [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {
    Write-Error "Windows Hello verification failed: $result"
    exit 1
}
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "KVSTORE_BIO_REASON="+reason)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg != "" {
			return fmt.Errorf("windows hello: %s", msg)
		}
		return fmt.Errorf("windows hello verification failed")
	}
	return nil
}

// HasBiometric reports whether Windows Hello is configured and available.
func (w *Windows) HasBiometric() bool {
	script := winRTPreamble + `
$result = Invoke-Async ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
if ($result -ne [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::Available) { exit 1 }
`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Run() == nil
}

// TPMSeal seals data to this machine's TPM 2.0 via Windows TBS.
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
