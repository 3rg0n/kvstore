---
title: kvstore
description: Lightweight, cross-platform encrypted key-value store with hardware-backed app access control.
version: 0.1.0
lang: go
go: "1.26"
license: MIT
platforms: [linux, darwin, windows]
architectures: [amd64, arm64]
tags: [kv-store, encryption, secrets, config-management, tpm, biometric, cli, rest-api]
---

# kvstore

A lightweight, cross-platform encrypted key-value store. Single binary, no dependencies. Supports app-level access control with token auth, namespace ACLs, and process attestation.

## Features

- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation
- **Cross-platform** — Windows, macOS, Linux; single binary, no CGO
- **Namespace support** — Organize secrets and config by project or environment
- **App access control** — Register apps with bearer tokens and namespace ACLs
- **Process attestation** — Verify caller binary via SHA-256 hash over IPC
- **HTTP API** — REST API with optional auth middleware
- **System service** — Install as a background service on any platform
- **TPM key sealing** — Seal master key to hardware (interface ready, stubs in place)
- **Biometric gating** — Windows Hello / Touch ID / FIDO2 for app registration (stubs in place)
- **Debug logging** — NDJSON structured logs with `--debug` flag

## Install

```bash
git clone https://github.com/ecopelan/kvstore.git
cd kvstore
make build        # → bin/kvstore
make build-all    # Cross-compile all 6 platform/arch combos
```

## Quick Start

```bash
# Initialize the store with a master password
kvstore init

# Initialize with TPM-sealed key (when hardware available)
kvstore init --tpm

# Store a secret
kvstore set secrets api-key "sk-12345"

# Retrieve it
kvstore get secrets api-key

# Retrieve with full metadata
kvstore get secrets api-key --json

# List namespaces
kvstore list

# List keys in a namespace
kvstore list secrets

# Delete a key
kvstore delete secrets api-key
```

## App Access Control

Register applications for authenticated API access. Each app gets a bearer token scoped to specific namespaces. Binary identity is verified via SHA-256 hash (or code signature for signed apps).

```bash
# Register an app — requires biometric or password confirmation
kvstore app register \
  --binary /usr/local/bin/myapp \
  --namespaces secrets,config \
  --name my-app
# → Prints a one-time token: kvs_abc123...

# List registered apps
kvstore app list

# Revoke an app
kvstore app revoke <app-id>

# Re-hash after binary update
kvstore app rehash <app-id>

# Change namespace ACLs
kvstore app update-ns <app-id> --namespaces secrets,config,logs
```

## HTTP API

```bash
# Start with app token authentication (default)
kvstore serve

# Start on a specific address
kvstore serve --addr 127.0.0.1:8080

# Start with debug logging (NDJSON to stdout)
kvstore serve --debug

# Start without auth (development only)
kvstore serve --no-auth
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/kv` | Yes | List namespaces |
| GET | `/api/v1/kv/{namespace}` | Yes | List keys in namespace |
| GET | `/api/v1/kv/{namespace}/{key}` | Yes | Get value |
| PUT | `/api/v1/kv/{namespace}/{key}` | Yes | Set value |
| DELETE | `/api/v1/kv/{namespace}/{key}` | Yes | Delete value |

### Authenticated Requests

```bash
# Set a value
curl -X PUT http://127.0.0.1:7390/api/v1/kv/secrets/db-password \
  -H "Authorization: Bearer kvs_your_token_here" \
  -H "Content-Type: application/json" \
  -d '{"value":"postgres123"}'

# Get a value
curl -H "Authorization: Bearer kvs_your_token_here" \
  http://127.0.0.1:7390/api/v1/kv/secrets/db-password

# List keys
curl -H "Authorization: Bearer kvs_your_token_here" \
  http://127.0.0.1:7390/api/v1/kv/secrets

# Delete
curl -X DELETE -H "Authorization: Bearer kvs_your_token_here" \
  http://127.0.0.1:7390/api/v1/kv/secrets/db-password
```

### Debug Logging

When `--debug` is enabled, the server outputs NDJSON to stdout:

```json
{"time":"...","level":"DEBUG","msg":"auth.request","method":"GET","path":"/api/v1/kv/secrets/api-key","token_present":true,"namespace":"secrets"}
{"time":"...","level":"DEBUG","msg":"auth.allowed","app_id":"uuid","app_name":"my-app","namespace":"secrets","verify_mode":"hash","binary_resolved":false}
{"time":"...","level":"DEBUG","msg":"http.request","method":"GET","path":"/api/v1/kv/secrets/api-key","status":200,"duration_ms":1}
```

## Security Model

| Layer | Protection |
|-------|-----------|
| **At rest** | AES-256-GCM encryption, Argon2id KDF (or TPM-sealed key) |
| **Token auth** | SHA-256 hashed bearer tokens, per-app namespace ACLs |
| **Process attestation** | Caller PID → binary path → SHA-256 hash verification (over IPC) |
| **Human gating** | Biometric/password confirmation for app registration and revocation |
| **Transport** | IPC only (named pipes / Unix sockets) — not exposed to network |

Over TCP (e.g. when `--addr` is specified), process attestation is unavailable — only token + namespace ACL enforcement applies. Full binary verification requires IPC listeners (named pipe on Windows, Unix socket on Linux/macOS).

## System Service

```bash
kvstore service install
kvstore service start
kvstore service stop
kvstore service status
kvstore service uninstall
```

When running as a service, provide the master password via environment variable:

```bash
export KVSTORE_KEY="your-master-password"
kvstore service install
kvstore service start
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KVSTORE_KEY` | Master password (avoids interactive prompt) |
| `KVSTORE_DATA_DIR` | Custom data directory path |

## Data Storage

| Platform | Default Path |
|----------|-------------|
| Linux | `~/.local/share/kvstore/store.db` |
| macOS | `~/Library/Application Support/kvstore/store.db` |
| Windows | `%APPDATA%\kvstore\store.db` |

## Development

```bash
make build        # Build for current platform
make build-all    # Cross-compile all platforms
make test         # Run unit tests with race detector
make test-e2e     # Run end-to-end test (14 test cases)
make lint         # golangci-lint
make vet          # go vet
make clean        # Remove build artifacts
```

### E2E Test

The e2e test builds two client binaries (one registered, one not), initializes a store, registers an app, starts the server with auth, and runs 14 test cases covering the full auth pipeline:

```bash
bash test/e2e.sh              # Normal run
DEBUG=true bash test/e2e.sh   # With NDJSON server log dump
```

## License

MIT
