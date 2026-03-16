package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ecopelan/kvstore/internal/store"
)

func setupMiddleware(t *testing.T) (*Middleware, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Init([]byte("testpassword")); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	reg := NewRegistry(s)
	binary := testBinaryPath(t)
	token, err := reg.Register("test-app", binary, []string{"secrets", "config"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	mw := NewMiddleware(reg, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	return mw, token
}

func dummyHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// setupMux creates a mux with auth-wrapped routes matching the real server pattern.
func setupMux(mw *Middleware) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", dummyHandler)
	mux.HandleFunc("GET /api/v1/kv", mw.RequireAuth(dummyHandler))
	mux.HandleFunc("GET /api/v1/kv/{namespace}", mw.RequireAuth(dummyHandler))
	mux.HandleFunc("GET /api/v1/kv/{namespace}/{key}", mw.RequireAuth(dummyHandler))
	mux.HandleFunc("PUT /api/v1/kv/{namespace}/{key}", mw.RequireAuth(dummyHandler))
	return mux
}

func TestMiddlewareNoAuthHeader(t *testing.T) {
	mw, _ := setupMiddleware(t)
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/key1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddlewareInvalidToken(t *testing.T) {
	mw, _ := setupMiddleware(t)
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/key1", nil)
	req.Header.Set("Authorization", "Bearer kvs_bogustoken")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddlewareMalformedAuthHeader(t *testing.T) {
	mw, _ := setupMiddleware(t)
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/key1", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for non-Bearer scheme, got %d", w.Code)
	}
}

func TestMiddlewareNamespaceDenied(t *testing.T) {
	mw, token := setupMiddleware(t)
	mux := setupMux(mw)

	// App has access to "secrets" and "config", not "other"
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/other/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong namespace, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddlewareValidAuth(t *testing.T) {
	mw, token := setupMiddleware(t)
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddlewareListNamespacesValidToken(t *testing.T) {
	mw, token := setupMiddleware(t)
	mux := setupMux(mw)

	// List namespaces (no namespace in path) — should just validate token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for list namespaces, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMiddlewareListNamespacesNoToken(t *testing.T) {
	mw, _ := setupMiddleware(t)
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for list namespaces without token, got %d", w.Code)
	}
}

func TestMiddlewareHealthUnauthenticated(t *testing.T) {
	mw, _ := setupMiddleware(t)
	mux := setupMux(mw)

	// Health endpoint is NOT wrapped with RequireAuth
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for health, got %d", w.Code)
	}
}

func TestMiddlewareAppRecordInContext(t *testing.T) {
	mw, token := setupMiddleware(t)

	var capturedRec *AppRecord
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		capturedRec = AppFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/kv/{namespace}/{key}", handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if capturedRec == nil {
		t.Fatal("expected AppRecord in context")
	}
	if capturedRec.Name != "test-app" {
		t.Errorf("expected app name 'test-app', got %q", capturedRec.Name)
	}
}

func TestMiddlewareWildcardNamespace(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Init([]byte("testpassword")); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	reg := NewRegistry(s)
	binary := testBinaryPath(t)
	token, err := reg.Register("admin", binary, []string{"*"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	mw := NewMiddleware(reg, nil, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	mux := setupMux(mw)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/any-namespace/key1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for wildcard namespace, got %d: %s", w.Code, w.Body.String())
	}
}
