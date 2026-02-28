---
title: CLAUDE.md
description: Development guidance for Claude Code (claude.ai/code) operating in this repository.
project: kvstoremon
lang: go
go: "1.26"
module: github.com/ecopelan/kvstoremon
entry: cmd/kvstoremon/main.go
store: bbolt
encryption: AES-256-GCM
kdf: Argon2id
dependencies:
  - github.com/spf13/cobra
  - go.etcd.io/bbolt
  - github.com/kardianos/service
  - golang.org/x/crypto
  - golang.org/x/term
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
make build          # Build for current platform → bin/kvstoremon
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

- `cmd/kvstoremon/main.go` — CLI entry point. All cobra commands (init, set, get, delete, list, serve, service, version) live here. Uses `kardianos/service` for cross-platform OS service integration.
- `internal/crypto` — AES-256-GCM encryption with Argon2id key derivation. Stateless functions.
- `internal/store` — Core KV store backed by bbolt. Handles encryption at the storage layer: values are JSON-marshaled `Entry` structs encrypted before writing. Namespaces map to bbolt buckets. `_meta` bucket stores salt and verification token.
- `internal/server` — HTTP REST API using Go 1.22+ stdlib routing (`http.ServeMux` with method+path patterns). Binds to localhost only by default.
- `internal/config` — Platform-specific data directory resolution (XDG on Linux, Library on macOS, APPDATA on Windows).
- `internal/service` — Thin wrapper around `kardianos/service` for OS service install/uninstall.

### Data Flow

1. `kvstoremon init` → user provides password → Argon2id derives key from password+random salt → verification token encrypted with key → salt and encrypted token stored in `_meta` bucket
2. On unlock → salt read from `_meta` → key re-derived → verification token decrypted to confirm correct password
3. Set/Get → entry JSON marshaled → encrypted with AES-256-GCM (random nonce per write) → stored in namespace bucket
4. HTTP API delegates directly to store methods — no additional auth layer (localhost-only)

### Key Design Decisions

- **bbolt** over SQLite: pure Go, no CGO, single-file embedded KV — true single binary cross-compilation
- **stdlib router** (Go 1.22+): eliminates chi/gorilla dependency for HTTP routing
- **Namespace = bbolt bucket**: natural isolation, efficient key enumeration per namespace
- **Password via env var** (`KVSTOREMON_KEY`): required for service mode, optional interactive prompt for CLI
- **`kardianos/service`**: unified service management across Windows SCM, systemd, launchd
