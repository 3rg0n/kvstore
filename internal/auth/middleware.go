package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

type contextKey string

const appRecordCtxKey contextKey = "app_record"

type connCtxKey struct{}

// ProcessVerifier resolves a network connection to a binary path.
// Implemented by platform.Platform.
type ProcessVerifier interface {
	PeerPID(conn net.Conn) (int, error)
	ProcessPath(pid int) (string, error)
}

// Middleware validates app tokens and namespace ACLs on HTTP requests.
type Middleware struct {
	registry *Registry
	verifier ProcessVerifier // nil = skip binary verification
	logger   *slog.Logger
}

// NewMiddleware creates auth middleware backed by the given registry.
// If verifier is non-nil, binary identity is verified via process attestation.
func NewMiddleware(registry *Registry, verifier ProcessVerifier, logger *slog.Logger) *Middleware {
	return &Middleware{registry: registry, verifier: verifier, logger: logger}
}

// ConnContext returns a function suitable for http.Server.ConnContext that
// injects each connection into the request context. This enables the
// middleware to retrieve the peer PID for process attestation.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, connCtxKey{}, conn)
}

// RequireAuth wraps a handler with token and namespace ACL verification.
// The namespace is extracted from r.PathValue("namespace"); if empty (e.g.
// list-namespaces endpoint), only the token is validated.
// When a ProcessVerifier is configured, the caller's binary path is resolved
// from the connection and verified against the app record.
func (m *Middleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		namespace := r.PathValue("namespace")

		m.logger.Debug("auth.request",
			"method", r.Method,
			"path", r.URL.Path,
			"token_present", token != "",
			"namespace", namespace)

		if token == "" {
			m.logger.Debug("auth.denied", "reason", "missing token")
			writeAuthError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
			return
		}

		// Attempt to resolve caller binary path via process attestation
		binaryPath := m.resolveBinaryPath(r.Context())

		rec, err := m.registry.Verify(token, binaryPath, namespace)
		if err != nil {
			m.logger.Debug("auth.denied",
				"reason", err.Error(),
				"namespace", namespace,
				"binary_resolved", binaryPath != "")
			switch err {
			case ErrInvalidToken:
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
			case ErrNamespaceDenied:
				writeAuthError(w, http.StatusForbidden, "namespace access denied")
			case ErrBinaryMismatch:
				writeAuthError(w, http.StatusForbidden, "binary verification failed")
			default:
				writeAuthError(w, http.StatusInternalServerError, "auth verification error")
			}
			return
		}

		m.logger.Debug("auth.allowed",
			"app_id", rec.ID,
			"app_name", rec.Name,
			"namespace", namespace,
			"verify_mode", rec.VerifyMode,
			"binary_resolved", binaryPath != "")

		ctx := context.WithValue(r.Context(), appRecordCtxKey, rec)
		next(w, r.WithContext(ctx))
	}
}

// resolveBinaryPath attempts to get the caller's binary path from the
// connection stored in context. Returns empty string if unavailable.
func (m *Middleware) resolveBinaryPath(ctx context.Context) string {
	if m.verifier == nil {
		return ""
	}

	conn, ok := ctx.Value(connCtxKey{}).(net.Conn)
	if !ok || conn == nil {
		return ""
	}

	pid, err := m.verifier.PeerPID(conn)
	if err != nil {
		m.logger.Debug("auth.binary_resolve", "step", "PeerPID", "err", err)
		return ""
	}

	path, err := m.verifier.ProcessPath(pid)
	if err != nil {
		m.logger.Debug("auth.binary_resolve", "step", "ProcessPath", "pid", pid, "err", err)
		return ""
	}

	m.logger.Debug("auth.binary_resolve", "pid", pid, "path", path)
	return path
}

// AppFromContext retrieves the verified AppRecord from the request context.
// Returns nil if no auth middleware ran or verification was skipped.
func AppFromContext(ctx context.Context) *AppRecord {
	rec, _ := ctx.Value(appRecordCtxKey).(*AppRecord)
	return rec
}

func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

type authErrorResponse struct {
	Error string `json:"error"`
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(authErrorResponse{Error: msg})
}
