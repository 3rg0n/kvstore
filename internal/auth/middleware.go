package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const appRecordCtxKey contextKey = "app_record"

// Middleware validates app tokens and namespace ACLs on HTTP requests.
type Middleware struct {
	registry *Registry
}

// NewMiddleware creates auth middleware backed by the given registry.
func NewMiddleware(registry *Registry) *Middleware {
	return &Middleware{registry: registry}
}

// RequireAuth wraps a handler with token and namespace ACL verification.
// The namespace is extracted from r.PathValue("namespace"); if empty (e.g.
// list-namespaces endpoint), only the token is validated.
// Binary identity verification is deferred to Step 3 (process attestation).
func (m *Middleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			writeAuthError(w, http.StatusUnauthorized, "missing or invalid Authorization header")
			return
		}

		namespace := r.PathValue("namespace")

		// Empty binaryPath: skip binary verification (no process attestation yet)
		rec, err := m.registry.Verify(token, "", namespace)
		if err != nil {
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

		ctx := context.WithValue(r.Context(), appRecordCtxKey, rec)
		next(w, r.WithContext(ctx))
	}
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
