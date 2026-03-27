//go:build linux

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

const binaryFreshnessThreshold = 2 * time.Second

// hashBinarySecure computes the SHA-256 hash with TOC-TOU mitigations.
// On Linux, when callerPID > 0, hashes directly from /proc/PID/exe which
// reads the kernel's cached inode — immune to filesystem path swaps.
// Falls back to the resolved path for registration-time hashing (PID=0).
func hashBinarySecure(binaryPath string, callerPID int) (string, error) {
	hashPath := filepath.Clean(binaryPath)

	// Use /proc/PID/exe directly for runtime verification.
	// This reads the kernel's inode, not the filesystem path, so an attacker
	// cannot swap the binary between ProcessPath() and hash computation.
	if callerPID > 0 {
		hashPath = fmt.Sprintf("/proc/%d/exe", callerPID)
	}

	// Freshness check on the resolved path (not /proc path which has no mtime)
	if callerPID == 0 {
		info, err := os.Stat(hashPath)
		if err != nil {
			return "", fmt.Errorf("stat binary: %w", err)
		}
		if time.Since(info.ModTime()) < binaryFreshnessThreshold {
			return "", fmt.Errorf("binary was modified %v ago (threshold %v): possible swap attack",
				time.Since(info.ModTime()).Round(time.Millisecond), binaryFreshnessThreshold)
		}
	}

	f, err := os.Open(hashPath) //nolint:gosec // path is /proc/PID/exe or cleaned
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
