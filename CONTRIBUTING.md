# Contributing to kvstore

Thank you for your interest in contributing to kvstore.

## Getting Started

1. Fork and clone the repository
2. Install Go 1.26+ and golangci-lint v2
3. Run `make test` to verify your setup

## Development Workflow

1. Create a branch from `master`
2. Make your changes
3. Ensure all checks pass before submitting:

```bash
make test         # Unit tests with race detector
make lint         # golangci-lint v2
make vet          # go vet
go build ./...    # Verify compilation
```

4. Open a pull request against `master`

## Code Standards

### Go Conventions

- Follow standard Go style (`gofmt`, `go vet`)
- All code must pass `golangci-lint` with the project's v2 config
- Use `go test -race` -- all tests must be race-free
- Prefer stdlib where practical (e.g., `net/http` routing over frameworks)

### Architecture

- **Package boundaries matter.** Each internal package has a clear responsibility. Don't leak concerns across packages.
- **Interface-driven decoupling.** Platform, store, and auth interact through small interfaces (`KeySealer`, `ProcessVerifier`, `AppStore`), not concrete types.
- **Build tags for platform code.** OS-specific implementations use build tags (`darwin && cgo`, `windows`, `linux`). Provide stubs with clear error messages when a feature isn't available.

### Security

- No secrets in code or test fixtures
- Validate at system boundaries (user input, external APIs)
- Use constant-time comparison for tokens and hashes
- Don't weaken IPC security (SDDL ACLs, Unix socket permissions)
- Review OWASP top 10 for any HTTP-facing changes

### Commit Messages

- Use imperative mood ("Add feature", not "Added feature")
- Keep the subject line under 72 characters
- Reference issues where applicable

## Project Structure

```
cmd/kvstore/          CLI + TUI entry point
internal/
  tui/                Bubble Tea terminal interface
  store/              bbolt-backed encrypted KV store
  crypto/             AES-256-GCM + Argon2id key derivation
  auth/               App registry, HTTP middleware, code signing
  server/             HTTP REST API
  platform/           OS abstraction layer (IPC, biometric, TPM)
  config/             Platform-specific path resolution
  service/            OS service management
test/
  cmd/                E2E test client binaries
  e2e.sh              End-to-end test script
```

## Testing

### Unit Tests

```bash
make test
# or run a specific test:
go test ./internal/store -run TestSetGetDelete -v
```

### End-to-End Tests

```bash
make test-e2e
```

The e2e suite builds test client binaries, initializes a store, registers an app, starts the server, and runs the full auth pipeline.

### Platform-Specific Tests

Biometric and TPM tests require real hardware and are gated behind environment variables:

```bash
KVSTORE_TEST_BIOMETRIC=1 go test ./internal/platform -run TestBiometric -v
```

## Adding a New Platform Feature

1. Define or extend the method in `internal/platform/platform.go` (the `Platform` interface)
2. Add the real implementation in the platform-specific file (`platform_windows.go`, `platform_darwin.go`, `platform_linux.go`) with appropriate build tags
3. Add a stub in the fallback file (e.g., `tpm_stub.go` for `darwin && !cgo`) that returns a clear error
4. Update `internal/tui/settings.go` if the feature has a capability check
5. Add tests gated behind an environment variable if hardware is required

## Reporting Issues

Open an issue on GitHub with:
- Platform and Go version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (use `kvstore serve --debug` for server issues)
