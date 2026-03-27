//go:build !linux && !windows

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// binaryFreshnessThreshold rejects binaries modified within this duration.
// Mitigates TOC-TOU swap attacks by detecting recently-written files.
const binaryFreshnessThreshold = 2 * time.Second

// hashBinarySecure computes the SHA-256 hash with TOC-TOU mitigations.
// On this platform (macOS), opens read-only and checks freshness.
// Freshness check only applies during runtime verification (callerPID > 0).
func hashBinarySecure(binaryPath string, callerPID int) (string, error) {
	cleanPath := filepath.Clean(binaryPath)

	if callerPID > 0 {
		info, err := os.Stat(cleanPath)
		if err != nil {
			return "", fmt.Errorf("stat binary: %w", err)
		}
		if time.Since(info.ModTime()) < binaryFreshnessThreshold {
			return "", fmt.Errorf("binary was modified %v ago (threshold %v): possible swap attack",
				time.Since(info.ModTime()).Round(time.Millisecond), binaryFreshnessThreshold)
		}
	}

	f, err := os.Open(cleanPath) //nolint:gosec // path is cleaned
	if err != nil {
		return "", fmt.Errorf("opening binary: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
