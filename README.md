---
title: kvstore
description: Lightweight, cross-platform encrypted key-value store for local-first secret and configuration management.
version: 0.1.0
lang: go
go: "1.26"
license: MIT
platforms: [linux, darwin, windows]
architectures: [amd64, arm64]
tags: [kv-store, encryption, secrets, config-management, tpm, cli, rest-api]
---

# kvstore

A lightweight, cross-platform encrypted key-value store. Local-first secret and configuration management with a single binary.

## Features

- **Encrypted at rest** — AES-256-GCM with Argon2id key derivation
- **Cross-platform** — Windows, macOS, Linux; single binary, no dependencies
- **Namespace support** — Organize secrets and config by project or environment
- **HTTP API** — REST API for programmatic access from any language
- **System service** — Install as a background service on any platform
- **TPM-ready** — Architecture designed for future TPM seal/unseal integration

## Install

### Build from source

```bash
git clone https://github.com/ecopelan/kvstore.git
cd kvstore
make build
```

### Cross-compile all platforms

```bash
make build-all
```

Produces binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.

## Quick Start

```bash
# Initialize the store with a master password
kvstore init

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

## HTTP API

Start the API server:

```bash
kvstore serve
kvstore serve --addr 127.0.0.1:8080
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/kv` | List namespaces |
| GET | `/api/v1/kv/{namespace}` | List keys in namespace |
| GET | `/api/v1/kv/{namespace}/{key}` | Get value |
| PUT | `/api/v1/kv/{namespace}/{key}` | Set value |
| DELETE | `/api/v1/kv/{namespace}/{key}` | Delete value |

### Examples

```bash
# Set a value
curl -X PUT http://127.0.0.1:7390/api/v1/kv/secrets/db-password \
  -H "Content-Type: application/json" \
  -d '{"value":"postgres123"}'

# Get a value
curl http://127.0.0.1:7390/api/v1/kv/secrets/db-password

# List keys
curl http://127.0.0.1:7390/api/v1/kv/secrets

# Delete
curl -X DELETE http://127.0.0.1:7390/api/v1/kv/secrets/db-password
```

## System Service

```bash
# Install as a system service
kvstore service install

# Manage the service
kvstore service start
kvstore service stop
kvstore service status

# Uninstall
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
make test     # Run tests with race detector
make vet      # Static analysis
make lint     # golangci-lint (requires golangci-lint installed)
make build    # Build for current platform
make clean    # Remove build artifacts
```

## License

MIT
