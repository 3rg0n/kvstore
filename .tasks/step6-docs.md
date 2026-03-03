# Step 6: Documentation + Integration Tests

## Status: COMPLETE

## Files Created
- `internal/server/server_integration_test.go` — End-to-end integration test covering the full auth pipeline: init → register app → serve with auth → authenticated requests → ACL enforcement → revocation. 12 subtests.

## Files Modified
- `CLAUDE.md` — Updated with new architecture: auth, platform, TPM packages. Updated data flow (password + TPM paths, app registration, HTTP auth flow). Added new design decisions (AppStore/KeySealer/ProcessVerifier interfaces, dual verify modes, ConnContext pattern). Added full CLI command reference.

## Integration Test Coverage
1. Health endpoint is unauthenticated (200)
2. No token returns 401
3. Invalid token returns 401
4. Valid token + allowed namespace returns data (200)
5. Valid token + denied namespace returns 403
6. Admin wildcard token accesses any namespace (200)
7. Write with valid auth (200)
8. Write to denied namespace returns 403
9. List namespaces with valid token (200)
10. Delete with valid auth (200)
11. Revoke then access returns 401

## Verification
- `go test ./... -race -count=1` — All tests pass (auth: 16, crypto, platform: 5, server: 23 including 12 integration, store: 15)
- `golangci-lint run ./...` — 0 issues
