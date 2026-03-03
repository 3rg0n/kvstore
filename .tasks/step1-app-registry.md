# Step 1: App Registry + Namespace ACLs

## Status: COMPLETE

## Files Changed
- `internal/store/store.go` — Added `_apps` bucket constant, `PutAppRecord`, `GetAppRecord`, `DeleteAppRecord`, `ListAppRecords` methods. Updated `ListNamespaces` to exclude `_apps`.
- `internal/auth/registry.go` — New package. `AppRecord` struct with dual verify modes (hash/signature). `Registry` type with `Register`, `Revoke`, `Rehash`, `UpdateNamespaces`, `List`, `Verify` methods. `HashBinary` and `CheckSignature` (stub) helpers. Token generation with `kvs_` prefix, stored as SHA-256 hash.
- `internal/auth/registry_test.go` — 16 tests covering register, list, auto-mode, verify (success, invalid token, binary mismatch, namespace denied, wildcard), revoke, rehash, update namespaces, multiple apps, hash binary, apps excluded from namespace listing.
- `cmd/kvstoremon/main.go` — Added `app` command group with `register`, `list`, `revoke`, `rehash`, `update-ns` subcommands. Biometric placeholder uses password re-confirmation.
- `go.mod` / `go.sum` — Added `github.com/google/uuid v1.6.0`.

## Design Decisions
- **AppStore interface**: Registry depends on an interface, not concrete Store, for testability
- **Token format**: `kvs_` prefix + 64 hex chars (32 random bytes). Only the SHA-256 hash is stored.
- **Namespace wildcard**: `"*"` grants access to all namespaces
- **CheckSignature stub**: Always returns unsigned. Platform implementations come in Step 3/4.
- **VerifyAuto**: Resolved at registration time — stored record always has `hash` or `signature`
- **Biometric placeholder**: Password re-confirmation (replaced by real biometric in Step 4)

## Verification
- `go test ./... -race -count=1` — 31 tests pass (16 auth + 9 store + 6 server)
- `golangci-lint run ./...` — 0 issues
- `go build ./cmd/kvstoremon/` — builds clean
- CLI commands: `app register`, `app list`, `app revoke`, `app rehash`, `app update-ns` all functional
