package platform

import (
	"os"
	"runtime"
	"testing"
)

func TestNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
}

func TestProcessPathSelf(t *testing.T) {
	p := New()

	pid := os.Getpid()
	path, err := p.ProcessPath(pid)
	if runtime.GOOS == "windows" {
		// Windows ProcessPath uses QueryFullProcessImageNameW which works for own PID
		if err != nil {
			t.Fatalf("ProcessPath(%d): %v", pid, err)
		}
		if path == "" {
			t.Error("expected non-empty path for own process")
		}
		t.Logf("own process path: %s", path)
	} else {
		// On Linux/Darwin, ProcessPath should work for own PID
		if err != nil {
			t.Fatalf("ProcessPath(%d): %v", pid, err)
		}
		if path == "" {
			t.Error("expected non-empty path for own process")
		}
	}
}

func TestHasBiometric(t *testing.T) {
	p := New()
	// HasBiometric should return a bool without panicking
	_ = p.HasBiometric()
}

func TestBiometricPromptStub(t *testing.T) {
	p := New()
	// Stub should succeed without error
	if err := p.BiometricPrompt("test verification"); err != nil {
		t.Fatalf("BiometricPrompt: %v", err)
	}
}

func TestListenerStub(t *testing.T) {
	p := New()

	// On Windows, Listener currently returns a TCP stub.
	// On Linux/Darwin, it creates a Unix socket.
	ln, err := p.Listener("kvstore-test")
	if runtime.GOOS == "windows" {
		// TCP stub
		if err != nil {
			t.Fatalf("Listener: %v", err)
		}
		defer func() { _ = ln.Close() }()
		t.Logf("listener addr: %s", ln.Addr())
	} else {
		// Unix socket — we'd need a real path for this
		// Skip on non-Windows for now since it needs a writable path
		if err != nil {
			t.Skipf("Listener: %v (expected on some platforms)", err)
		}
		defer func() { _ = ln.Close() }()
	}
}
