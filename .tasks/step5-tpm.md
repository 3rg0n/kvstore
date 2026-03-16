# Step 5: TPM Master Key Sealing

## Status: COMPLETE

## Files Created
- `internal/platform/tpm_stub.go` — Shared XOR-based seal/unseal stub used by all platforms until real TPM is integrated. NOT secure, only structural.

## Files Modified
- `internal/platform/platform.go` — Added TPMSeal, TPMUnseal, HasTPM to Platform interface.
- `internal/platform/platform_windows.go` — TPM stub methods. HasTPM returns false (planned: TBS interface).
- `internal/platform/platform_darwin.go` — TPM stub methods. HasTPM returns false (planned: Secure Enclave via swift).
- `internal/platform/platform_linux.go` — TPM stub methods. HasTPM returns false (planned: /dev/tpmrm0 via go-tpm-tools).
- `internal/store/store.go` — Added KeySealer interface, InitTPM(), UnlockTPM(), IsTPMMode(). New _meta keys: mode, sealed_key. ModePassword/ModeTPM exported constants.
- `internal/store/store_test.go` — Added TestInitTPMAndUnlock, TestPasswordModeNotTPM, TestDoubleInitTPM with mockSealer.
- `cmd/kvstore/main.go` — Added --tpm flag to init. Auto-detect TPM hint. openAndUnlock() auto-detects TPM mode and uses UnlockTPM.

## Design Decisions
- **KeySealer interface**: Store depends on a small interface (TPMSeal/TPMUnseal), not the full Platform. Keeps store decoupled from platform.
- **TPM Init flow**: Generate random 32-byte key → seal with TPM → store sealed blob + encrypted verification token. No password needed.
- **TPM Unlock flow**: Read sealed blob → unseal with TPM → verify decryption → set s.key.
- **Auto-detection**: openAndUnlock checks IsTPMMode() to choose between password and TPM unlock. CLI init auto-detects and suggests --tpm.
- **Stubs return false for HasTPM**: No real TPM available until go-tpm-tools is integrated. XOR stub allows testing the code paths.

## Verification
- `go test ./... -race -count=1` — All tests pass (12 store including 3 new TPM tests)
- `golangci-lint run ./...` — 0 issues
- Cross-compilation: linux/amd64, darwin/arm64 — OK
