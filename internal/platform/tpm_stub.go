package platform

// tpmSealStub and tpmUnsealStub provide a reversible transformation as a
// structural placeholder for real TPM sealing. They are NOT cryptographically
// secure — they exist only to validate the Init/Unlock TPM code paths until
// google/go-tpm-tools is integrated.
//
// The stub uses a fixed XOR key so that seal/unseal round-trips correctly.
// Real TPM sealing binds data to the hardware's storage root key (SRK).

var tpmStubKey = []byte("kvstore-tpm-stub-placeholder!") // 32 bytes

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
