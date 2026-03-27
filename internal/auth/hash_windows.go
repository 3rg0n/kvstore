//go:build windows

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const binaryFreshnessThreshold = 2 * time.Second

// hashBinarySecure computes the SHA-256 hash with TOC-TOU mitigations.
// On Windows, opens the binary with FILE_SHARE_READ only (deny write/delete),
// preventing an attacker from swapping the file during hash computation.
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

	// Open with FILE_SHARE_READ only — blocks other processes from writing
	// or deleting the file while we hash it.
	pathUTF16, err := windows.UTF16PtrFromString(cleanPath)
	if err != nil {
		return "", fmt.Errorf("encoding path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ, // deny write and delete
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("opening binary (deny-write): %w", err)
	}

	f := os.NewFile(uintptr(handle), cleanPath)
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
