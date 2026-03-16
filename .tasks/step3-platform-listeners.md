# Step 3: Platform Listener + Process Verification

## Status: COMPLETE

## Files Created
- `internal/platform/platform.go` — Platform interface with Listener, PeerPID, ProcessPath methods.
- `internal/platform/platform_windows.go` — Windows: TCP stub listener (named pipe via go-winio planned), GetNamedPipeClientProcessId for PeerPID, QueryFullProcessImageNameW for ProcessPath. Build-tagged.
- `internal/platform/platform_darwin.go` — macOS: Unix socket listener, LOCAL_PEERPID via getsockopt, proc_info PROC_PIDPATHINFO syscall for ProcessPath. Build-tagged.
- `internal/platform/platform_linux.go` — Linux: Unix socket listener, SO_PEERCRED via GetsockoptUcred, /proc/{pid}/exe readlink for ProcessPath. Build-tagged.
- `internal/platform/platform_test.go` — Tests: New(), ProcessPath(self), Listener.

## Files Modified
- `internal/auth/middleware.go` — Added ProcessVerifier interface, ConnContext function for http.Server.ConnContext, resolveBinaryPath from connection context. NewMiddleware now accepts optional verifier + logger.
- `internal/auth/middleware_test.go` — Updated for new NewMiddleware signature.
- `internal/auth/registry.go` — Nolint annotation on filepath.Clean.
- `internal/server/server.go` — Start() now accepts net.Listener. ConnContext set on http.Server when auth middleware is active.
- `internal/config/config.go` — Added SocketPath() for platform-specific IPC path.
- `cmd/kvstore/main.go` — serveProgram creates platform listener when auth enabled, falls back to TCP. Imports platform package.
- `go.mod` — golang.org/x/sys promoted to direct dependency.

## Design Decisions
- **ProcessVerifier interface**: Small interface (PeerPID + ProcessPath) in auth package avoids coupling to platform package.
- **ConnContext injection**: Uses http.Server.ConnContext to store net.Conn in request context, enabling middleware to resolve PID → binary path.
- **Graceful degradation**: If PeerPID or ProcessPath fails (e.g. TCP connection on Windows stub), binary path returns empty → binary verification skipped. Token + namespace ACL still enforced.
- **Windows TCP stub**: Named pipe listener requires go-winio; TCP stub allows auth flow to work while process verification degrades gracefully.
- **Cross-compilation**: All platform files use build tags, verified: linux/amd64, darwin/arm64, windows/amd64.

## Verification
- `go test ./... -race -count=1` — All tests pass (26 auth + 3 platform + 9 store + 6 server + 6 crypto)
- `golangci-lint run ./...` — 0 issues
- `GOOS=linux go build ./...` — OK
- `GOOS=darwin go build ./...` — OK
- ProcessPath resolves own test binary on Windows
