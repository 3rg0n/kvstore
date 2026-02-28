# kvstoremon

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
git clone https://github.com/ecopelan/kvstoremon.git
cd kvstoremon
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
kvstoremon init

# Store a secret
kvstoremon set secrets api-key "sk-12345"

# Retrieve it
kvstoremon get secrets api-key

# Retrieve with full metadata
kvstoremon get secrets api-key --json

# List namespaces
kvstoremon list

# List keys in a namespace
kvstoremon list secrets

# Delete a key
kvstoremon delete secrets api-key
```

## HTTP API

Start the API server:

```bash
kvstoremon serve
kvstoremon serve --addr 127.0.0.1:8080
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
kvstoremon service install

# Manage the service
kvstoremon service start
kvstoremon service stop
kvstoremon service status

# Uninstall
kvstoremon service uninstall
```

When running as a service, provide the master password via environment variable:

```bash
export KVSTOREMON_KEY="your-master-password"
kvstoremon service install
kvstoremon service start
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KVSTOREMON_KEY` | Master password (avoids interactive prompt) |
| `KVSTOREMON_DATA_DIR` | Custom data directory path |

## Data Storage

| Platform | Default Path |
|----------|-------------|
| Linux | `~/.local/share/kvstoremon/store.db` |
| macOS | `~/Library/Application Support/kvstoremon/store.db` |
| Windows | `%APPDATA%\kvstoremon\store.db` |

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
