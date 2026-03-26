# kvstore

A lightweight, cross-platform encrypted key-value store. Single binary, no external runtime dependencies. Supports hardware-backed key sealing, biometric gating, app-level access control with token auth, namespace ACLs, and process attestation.

## Features

- **Encrypted at rest** -- AES-256-GCM with Argon2id key derivation
- **Hardware key sealing** -- TPM 2.0 (Windows/Linux), Secure Enclave (macOS) for master key protection
- **Biometric gating** -- Windows Hello, Touch ID, fprintd for human-presence verification
- **Interactive TUI** -- Full terminal UI via Bubble Tea; run `kvstore` with no args
- **Cross-platform** -- Windows, macOS, Linux (amd64 + arm64)
- **Namespace isolation** -- Organize secrets and config by project or environment
- **App access control** -- Register apps with bearer tokens and namespace ACLs
- **Process attestation** -- Verify caller binary via SHA-256 hash or code signature over IPC
- **Code signing verification** -- macOS `codesign` and Windows Authenticode identity checks
- **HTTP API** -- REST API with optional auth middleware
- **IPC transport** -- Named pipes (Windows) and Unix sockets (Linux/macOS) for secure local communication
- **System service** -- Install as a background service on any platform (SCM, systemd, launchd)
- **Debug logging** -- NDJSON structured logs with `--debug` flag

## Install

```bash
git clone https://github.com/3rg0n/kvstore.git
cd kvstore
make build        # -> bin/kvstore
make build-all    # Cross-compile all 6 platform/arch combos
```

Requires Go 1.26+. macOS Secure Enclave and Touch ID features require CGO (`CGO_ENABLED=1`); all other features build without CGO.

## Quick Start

### Interactive TUI

```bash
# Launch the TUI -- no commands to memorize
kvstore
```

The TUI provides screens for store initialization, secrets browsing, app management, server control, and settings. Navigate with arrow keys, Enter, and Esc.

### CLI

```bash
# Initialize the store with a master password
kvstore init

# Initialize with hardware-sealed key (TPM/Secure Enclave)
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

Register applications for authenticated API access. Each app gets a bearer token scoped to specific namespaces. Binary identity is verified via SHA-256 hash or code signature (macOS codesign / Windows Authenticode).

```bash
# Register an app -- requires biometric or password confirmation
kvstore app register \
  --binary /usr/local/bin/myapp \
  --namespaces secrets,config \
  --name my-app \
  --verify auto
# -> Prints a one-time token: kvs_abc123...

# List registered apps
kvstore app list

# Revoke an app
kvstore app revoke <app-id>

# Re-hash after binary update
kvstore app rehash <app-id>

# Change namespace ACLs
kvstore app update-ns <app-id> --namespaces secrets,config,logs
```

Verify modes: `hash` (SHA-256 of binary, strictest), `signature` (code signing identity, survives updates), `auto` (signature if signed, hash otherwise).

## HTTP API

```bash
# Start with app token authentication (default, IPC listener)
kvstore serve

# Start on a specific TCP address
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
curl -X PUT http://127.0.0.1:7390/api/v1/kv/secrets/db-password \
  -H "Authorization: Bearer kvs_your_token_here" \
  -H "Content-Type: application/json" \
  -d '{"value":"postgres123"}'

curl -H "Authorization: Bearer kvs_your_token_here" \
  http://127.0.0.1:7390/api/v1/kv/secrets/db-password
```

## Security Model

| Layer | Protection |
|-------|-----------|
| **At rest** | AES-256-GCM encryption, Argon2id KDF (or TPM/Secure Enclave sealed key) |
| **Token auth** | SHA-256 hashed bearer tokens, per-app namespace ACLs |
| **Process attestation** | Caller PID -> binary path -> SHA-256 hash or code signature verification (IPC only) |
| **Human gating** | Biometric (Windows Hello / Touch ID / fprintd) or password for sensitive operations |
| **Transport** | IPC only by default (named pipes / Unix sockets) -- not exposed to network |

Over TCP (e.g. when `--addr` is specified), process attestation is unavailable -- only token + namespace ACL enforcement applies. Full binary verification requires IPC.

## Platform Support

| Feature | Windows | macOS | Linux |
|---------|---------|-------|-------|
| Encryption (AES-256-GCM) | Yes | Yes | Yes |
| Key sealing | TPM 2.0 | Secure Enclave (CGO) | TPM 2.0 |
| Biometric | Windows Hello | Touch ID (CGO) | fprintd |
| IPC | Named pipes | Unix socket | Unix socket |
| Code signing | Authenticode | codesign | -- |
| Service | SCM | launchd | systemd |

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
kvstore service install && kvstore service start
```

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `KVSTORE_KEY` | Master password (avoids interactive prompt; required for service mode) |
| `KVSTORE_DATA_DIR` | Custom data directory path |

### Data Storage

| Platform | Default Path |
|----------|-------------|
| Linux | `~/.local/share/kvstore/store.db` |
| macOS | `~/Library/Application Support/kvstore/store.db` |
| Windows | `%APPDATA%\kvstore\store.db` |

## Architecture

```
cmd/kvstore/          CLI entry point (Cobra) + TUI launcher
internal/
  tui/                Bubble Tea interactive interface
  store/              bbolt-backed encrypted KV store
  crypto/             AES-256-GCM + Argon2id
  auth/               App registry, HTTP auth middleware, code signing
  server/             HTTP REST API (stdlib router, Go 1.22+)
  platform/           OS abstraction (IPC, biometric, TPM, attestation)
  config/             Platform-specific paths
  service/            OS service management (kardianos/service)
```

## Development

```bash
make build        # Build for current platform
make build-all    # Cross-compile all platforms
make test         # Run unit tests with race detector
make test-e2e     # Run end-to-end test suite
make lint         # golangci-lint v2
make vet          # go vet
make clean        # Remove build artifacts
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

[MIT](LICENSE.md)
