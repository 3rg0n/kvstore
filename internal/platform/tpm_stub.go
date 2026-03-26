//go:build darwin && !cgo

package platform

import "errors"

// When CGO is disabled on macOS, Secure Enclave and Touch ID are unavailable.
// These stubs return clear errors instead of silently using fake crypto.

func enclaveSeal(_ []byte) ([]byte, error) {
	return nil, errors.New("secure enclave requires CGO (build with CGO_ENABLED=1)")
}

func enclaveUnseal(_ []byte) ([]byte, error) {
	return nil, errors.New("secure enclave requires CGO (build with CGO_ENABLED=1)")
}

func enclaveAvailable() bool {
	return false
}

func touchIDPrompt(_ string) error {
	return errors.New("touch id requires CGO (build with CGO_ENABLED=1)")
}

func touchIDAvailable() bool {
	return false
}
