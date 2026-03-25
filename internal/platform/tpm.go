//go:build windows || linux

package platform

// Real TPM 2.0 seal/unseal using google/go-tpm.
//
// Flow:
//   Seal:   OpenTPM → CreatePrimary (SRK) → Seal (data under SRK) → FlushContext → return (private || public)
//   Unseal: OpenTPM → CreatePrimary (SRK) → Load (sealed object) → Unseal → FlushContext → return plaintext
//
// The SRK is deterministic — same template + same TPM = same key every time.
// Sealed data is bound to this TPM's SRK and cannot be unsealed on another machine.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

// srkTemplate is the TCG-recommended RSA 2048 SRK template.
// Using the standard template ensures CreatePrimary produces the same key
// each time on the same TPM, so we don't need to persist the SRK handle.
var srkTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
		tpm2.FlagRestricted | tpm2.FlagDecrypt | tpm2.FlagNoDA,
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		KeyBits:    2048,
		ModulusRaw: make([]byte, 256),
	},
}

// sealedObjectTemplate is the template for a sealed data object.
// FlagUserWithAuth is required so Unseal works with a password session.
var sealedObjectTemplate = tpm2.Public{
	Type:       tpm2.AlgKeyedHash,
	NameAlg:    tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagUserWithAuth | tpm2.FlagNoDA,
}

// tpmSeal seals data to this machine's TPM using the SRK.
// Returns a blob containing length-prefixed private and public portions.
func tpmSeal(data []byte) ([]byte, error) {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = rwc.Close() }()

	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating SRK: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(rwc, srkHandle) }()

	private, public, _, _, _, err := tpm2.CreateKeyWithSensitive(rwc, srkHandle, tpm2.PCRSelection{}, "", "", sealedObjectTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("sealing data: %w", err)
	}

	// Encode as: [4 bytes private len][private][public]
	blob := make([]byte, 4+len(private)+len(public))
	binary.LittleEndian.PutUint32(blob[:4], uint32(len(private)))
	copy(blob[4:4+len(private)], private)
	copy(blob[4+len(private):], public)

	return blob, nil
}

// tpmUnseal recovers data from a blob produced by tpmSeal.
func tpmUnseal(sealed []byte) ([]byte, error) {
	if len(sealed) < 4 {
		return nil, errors.New("sealed blob too short")
	}

	privLen := int(binary.LittleEndian.Uint32(sealed[:4]))
	if len(sealed) < 4+privLen {
		return nil, errors.New("sealed blob truncated")
	}
	private := sealed[4 : 4+privLen]
	public := sealed[4+privLen:]

	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = rwc.Close() }()

	srkHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("creating SRK: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(rwc, srkHandle) }()

	objectHandle, _, err := tpm2.Load(rwc, srkHandle, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("loading sealed object: %w", err)
	}
	defer func() { _ = tpm2.FlushContext(rwc, objectHandle) }()

	data, err := tpm2.Unseal(rwc, objectHandle, "")
	if err != nil {
		return nil, fmt.Errorf("unsealing data: %w", err)
	}

	return data, nil
}

// tpmAvailable checks if a TPM 2.0 is present and accessible.
func tpmAvailable() bool {
	rwc, err := tpm2.OpenTPM()
	if err != nil {
		return false
	}
	_ = rwc.Close()
	return true
}
