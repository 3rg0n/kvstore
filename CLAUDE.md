---
title: CLAUDE.md
description: Development guidance for Claude Code (claude.ai/code) operating in this repository.
project: kvstore
lang: go
go: "1.26"
module: github.com/ecopelan/kvstore
entry: cmd/kvstore/main.go
store: bbolt
encryption: AES-256-GCM
kdf: Argon2id
dependencies:
  - github.com/spf13/cobra
  - go.etcd.io/bbolt
  - github.com/kardianos/service
  - golang.org/x/crypto
  - golang.org/x/term
  - github.com/google/uuid
  - golang.org/x/sys
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make build          # Build for current platform → bin/kvstore
make build-all      # Cross-compile linux/darwin/windows (amd64+arm64)
make test           # Run all tests with race detector
make vet            # go vet static analysis
make lint           # golangci-lint (v2 config)
make clean          # Remove bin/
```

Single test: `go test ./internal/store -run TestSetGetDelete -v`

## Architecture

Single-binary Go CLI + HTTP server for encrypted key-value storage. No external runtime dependencies.

### Package Layout

- `cmd/kvstore/main.go` — CLI entry point. All cobra commands (init, set, get, delete, list, serve, service, version, app) live here. Uses `kardianos/service` for cross-platform OS service integration. Includes `confirmIdentity()` helper (biometric-first, password-fallback).
- `internal/crypto` — AES-256-GCM encryption with Argon2id key derivation. Stateless functions.
- `internal/store` — Core KV store backed by bbolt. Handles encryption at the storage layer: values are JSON-marshaled `Entry` structs encrypted before writing. Namespaces map to bbolt buckets. `_meta` bucket stores salt, verification token, and mode (password/tpm). `_apps` bucket stores encrypted app registration records. Supports both password-derived and TPM-sealed master keys via `KeySealer` interface.
- `internal/auth` — App registry (`Registry`) and HTTP auth middleware (`Middleware`). Registry manages app records with dual verify modes (SHA-256 hash or code signature). Middleware extracts `Authorization: Bearer <token>`, validates against registry, enforces namespace ACLs, and optionally verifies caller binary via `ProcessVerifier` interface.
- `internal/platform` — OS abstraction layer with build-tagged implementations for Windows, macOS, and Linux. Provides `Platform` interface with: IPC listeners (named pipes/Unix sockets), process attestation (`PeerPID`, `ProcessPath`), biometric prompts, and TPM seal/unseal. Current implementations use stubs for biometric and TPM (structural, not yet hardware-backed).
- `internal/server` — HTTP REST API using Go 1.22+ stdlib routing (`http.ServeMux` with method+path patterns). Accepts a `net.Listener` (for platform-specific IPC) and optional `*auth.Middleware`. Health endpoint is always unauthenticated; KV routes are wrapped with auth when middleware is provided.
- `internal/config` — Platform-specific data directory and socket path resolution (XDG on Linux, Library on macOS, APPDATA on Windows). `SocketPath()` returns the IPC endpoint path.
- `internal/service` — Thin wrapper around `kardianos/service` for OS service install/uninstall.

### Data Flow

1. **Password init**: `kvstore init` → password → Argon2id derives key from password+salt → verification token encrypted → salt+token stored in `_meta`
2. **TPM init**: `kvstore init --tpm` → random 32-byte key generated → sealed with TPM → sealed blob + encrypted verification token stored in `_meta` (mode=tpm)
3. **Password unlock**: salt read → key re-derived → verification token decrypted
4. **TPM unlock**: sealed blob read → TPM unseal → key recovered → verification token decrypted
5. Set/Get → entry JSON marshaled → encrypted with AES-256-GCM (random nonce per write) → stored in namespace bucket
6. **App registration**: `kvstore app register --binary <path> --namespaces <ns>` → biometric/password confirmation → binary hashed or signature extracted → token generated (kvs_ prefix) → token hash + app record stored in `_apps` bucket
7. **HTTP auth flow**: request → extract `Bearer <token>` → resolve caller PID via IPC connection → get binary path → `Registry.Verify(token, binaryPath, namespace)` → match token hash → verify binary identity → check namespace ACL → allow or reject (401/403)

### Key Design Decisions

- **bbolt** over SQLite: pure Go, no CGO, single-file embedded KV — true single binary cross-compilation
- **stdlib router** (Go 1.22+): eliminates chi/gorilla dependency for HTTP routing
- **Namespace = bbolt bucket**: natural isolation, efficient key enumeration per namespace
- **Password via env var** (`KVSTORE_KEY`): required for service mode, optional interactive prompt for CLI
- **`kardianos/service`**: unified service management across Windows SCM, systemd, launchd
- **AppStore interface**: `auth.Registry` depends on a small interface (`PutAppRecord`, `GetAppRecord`, `DeleteAppRecord`, `ListAppRecords`), not the full `*store.Store` — keeps auth decoupled from storage
- **KeySealer interface**: Store depends on `TPMSeal`/`TPMUnseal` for hardware key binding, not the full Platform
- **ProcessVerifier interface**: Middleware depends on `PeerPID`/`ProcessPath` for process attestation, not the full Platform
- **Dual verify modes**: Hash mode (SHA-256 of binary, most secure) vs signature mode (code signing identity, survives updates)
- **ConnContext pattern**: `http.Server.ConnContext` injects `net.Conn` into request context for PID resolution without modifying handler signatures
- **`--no-auth` flag**: Backwards-compatible; nil middleware = no auth enforcement (for development/migration)
- **Biometric-first, password-fallback**: `confirmIdentity()` tries platform biometric, then re-enters master password

### CLI Commands

```
kvstore init [--tpm]                          # Initialize store (password or TPM-sealed)
kvstore set <namespace> <key> <value>         # Set a key-value pair
kvstore get <namespace> <key> [--json]         # Get a value
kvstore delete <namespace> <key>              # Delete a key
kvstore list [namespace]                      # List namespaces or keys
kvstore serve [--addr <addr>] [--no-auth]     # Start HTTP API server
kvstore service install|uninstall|start|stop|status  # OS service management
kvstore app register --binary <path> --namespaces <ns> [--name <n>] [--verify hash|signature|auto]
kvstore app list                              # List registered apps
kvstore app revoke <app-id>                   # Revoke app access
kvstore app rehash <app-id>                   # Re-hash binary after update
kvstore app update-ns <app-id> --namespaces <ns>  # Change namespace ACLs
kvstore version                               # Print version
```
