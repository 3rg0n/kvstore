# Step 2: Server Auth Middleware

## Status: COMPLETE

## Files Changed
- `internal/auth/middleware.go` — New. `Middleware` type with `RequireAuth` wrapper. Extracts `Authorization: Bearer <token>`, validates via registry, checks namespace ACL from path. Injects `AppRecord` into request context. Returns 401/403 JSON errors.
- `internal/auth/middleware_test.go` — New. 10 tests: no auth header (401), invalid token (401), malformed auth (401), namespace denied (403), valid auth (200), list namespaces with/without token, health unauthenticated, context injection, wildcard namespace.
- `internal/auth/registry.go` — Updated `Verify`: skips binary check when binaryPath is empty, skips namespace ACL when namespace is empty. Enables token-only verification before platform process attestation (Step 3).
- `internal/server/server.go` — `New()` now accepts `*auth.Middleware`. When non-nil, all KV routes are wrapped with `RequireAuth`. Health endpoint stays unauthenticated.
- `internal/server/server_test.go` — Updated to pass `nil` middleware (no auth in existing tests).
- `cmd/kvstoremon/main.go` — Added `--no-auth` flag to `serve` command. When not set, creates registry + middleware. Logs auth status on startup.

## Design Decisions
- **Binary verification deferred**: Middleware passes empty binaryPath to Verify, skipping binary hash check. Step 3 will wire in real process attestation via platform listeners.
- **Namespace from PathValue**: Uses `r.PathValue("namespace")` set by Go 1.22+ mux routing. Empty for list-namespaces endpoint → token-only validation.
- **nil middleware = no auth**: Server works identically to pre-auth behavior when middleware is nil, preserving backward compatibility for tests and --no-auth mode.
- **Error responses**: JSON format matching existing server error responses. 401 for missing/invalid token, 403 for namespace/binary denial.

## Verification
- `go test ./... -race -count=1` — All tests pass (26 auth + 9 store + 6 server)
- `golangci-lint run ./...` — 0 issues
- `go build ./cmd/kvstoremon/` — builds clean
