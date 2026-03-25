//go:build darwin

package platform

// tpmSealStub and tpmUnsealStub provide a reversible transformation as a
// structural placeholder for real Secure Enclave sealing on macOS.
// They are NOT cryptographically secure — they exist only to validate the
// Init/Unlock TPM code paths until CGO Secure Enclave integration lands.
//
// The stub uses a fixed XOR key so that seal/unseal round-trips correctly.

var tpmStubKey = []byte("kvstore-tpm-stub-placeholder!") // 29 bytes

func tpmSealStub(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ tpmStubKey[i%len(tpmStubKey)]
	}
	return out
}

func tpmUnsealStub(sealed []byte) []byte {
	// XOR is its own inverse
	return tpmSealStub(sealed)
}
