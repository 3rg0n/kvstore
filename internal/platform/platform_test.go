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
	if os.Getenv("KVSTORE_TEST_BIOMETRIC") == "" {
		t.Skip("skipping biometric test (set KVSTORE_TEST_BIOMETRIC=1 to run)")
	}
	p := New()
	// HasBiometric should return a bool without panicking
	t.Logf("HasBiometric: %v", p.HasBiometric())
}

func TestBiometricPrompt(t *testing.T) {
	if os.Getenv("KVSTORE_TEST_BIOMETRIC") == "" {
		t.Skip("skipping biometric test (set KVSTORE_TEST_BIOMETRIC=1 to run)")
	}
	p := New()
	if err := p.BiometricPrompt("kvstore test verification"); err != nil {
		t.Fatalf("BiometricPrompt: %v", err)
	}
}

func TestListener(t *testing.T) {
	p := New()

	if runtime.GOOS == "windows" {
		// Named pipe listener
		ln, err := p.Listener("kvstore-test")
		if err != nil {
			t.Fatalf("Listener: %v", err)
		}
		defer func() { _ = ln.Close() }()
		t.Logf("listener addr: %s", ln.Addr())
	} else {
		// Unix socket — needs a writable path
		ln, err := p.Listener("kvstore-test")
		if err != nil {
			t.Skipf("Listener: %v (expected on some platforms)", err)
		}
		defer func() { _ = ln.Close() }()
		t.Logf("listener addr: %s", ln.Addr())
	}
}
