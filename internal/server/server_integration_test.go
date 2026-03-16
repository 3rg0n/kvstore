package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ecopelan/kvstore/internal/auth"
	"github.com/ecopelan/kvstore/internal/store"
)

// TestIntegrationAuthFlow is an end-to-end test of the full auth pipeline:
// init → register app → serve with auth → authenticated requests → ACL enforcement.
func TestIntegrationAuthFlow(t *testing.T) {
	// 1. Set up store
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Init([]byte("test-password")); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// 2. Seed some data
	if err := s.Set("secrets", "api-key", []byte("sk-12345")); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := s.Set("config", "db-host", []byte("localhost:5432")); err != nil {
		t.Fatalf("set: %v", err)
	}

	// 3. Register an app with access to "secrets" only
	reg := auth.NewRegistry(s)
	testBinary := testBinaryPath(t)
	token, err := reg.Register("test-app", testBinary, []string{"secrets"}, auth.VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// 4. Register a second app with wildcard access
	adminToken, err := reg.Register("admin-app", testBinary, []string{"*"}, auth.VerifyHash)
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}

	// 5. Create server WITH auth middleware (no process verifier for httptest)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	mw := auth.NewMiddleware(reg, nil, logger)
	srv := New(s, logger, mw)
	mux := srv.http.Handler.(*http.ServeMux)

	// --- Test cases ---

	t.Run("health is unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("no token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/api-key", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/api-key", nil)
		req.Header.Set("Authorization", "Bearer kvs_invalid")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("valid token + allowed namespace returns data", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/api-key", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var resp kvResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.Value != "sk-12345" {
			t.Fatalf("expected sk-12345, got %q", resp.Value)
		}
	})

	t.Run("valid token + denied namespace returns 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/config/db-host", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("admin wildcard token accesses any namespace", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/config/db-host", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("write with valid auth", func(t *testing.T) {
		body := `{"value":"new-secret"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/secrets/new-key", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("write to denied namespace returns 403", func(t *testing.T) {
		body := `{"value":"hacked"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/config/evil", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("list namespaces with valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("delete with valid auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/kv/secrets/new-key", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("revoke then access returns 401", func(t *testing.T) {
		apps, err := reg.List()
		if err != nil {
			t.Fatalf("list apps: %v", err)
		}
		// Revoke test-app (first registered)
		for _, app := range apps {
			if app.Name == "test-app" {
				if err := reg.Revoke(app.ID); err != nil {
					t.Fatalf("revoke: %v", err)
				}
				break
			}
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/api-key", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after revoke, got %d: %s", w.Code, w.Body.String())
		}
	})
}

func testBinaryPath(t *testing.T) string {
	t.Helper()
	// Use any existing file as a stand-in binary for registration
	exe, err := filepath.Abs("server.go")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return exe
}
