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

	"github.com/ecopelan/kvstoremon/internal/store"
)

func testServer(t *testing.T) (*Server, *http.ServeMux) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Init([]byte("test-password")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := New(s, logger, nil)
	return srv, srv.http.Handler.(*http.ServeMux)
}

func decodeJSON(t *testing.T, r io.Reader, v any) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func TestHealth(t *testing.T) {
	_, mux := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	decodeJSON(t, w.Body, &resp)
	if resp["status"] != "ok" {
		t.Fatalf("got %q, want %q", resp["status"], "ok")
	}
}

func TestSetAndGet(t *testing.T) {
	_, mux := testServer(t)

	// Set
	body := `{"value":"my-secret"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/secrets/api-key", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("set status: got %d, want %d, body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Get
	req = httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/api-key", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("get status: got %d, want %d", w.Code, http.StatusOK)
	}

	var resp kvResponse
	decodeJSON(t, w.Body, &resp)
	if resp.Value != "my-secret" {
		t.Fatalf("got %q, want %q", resp.Value, "my-secret")
	}
	if resp.Namespace != "secrets" {
		t.Fatalf("namespace: got %q, want %q", resp.Namespace, "secrets")
	}
}

func TestGetNotFound(t *testing.T) {
	_, mux := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/secrets/missing", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteAndList(t *testing.T) {
	_, mux := testServer(t)

	// Set two keys
	for _, key := range []string{"key1", "key2"} {
		body := `{"value":"val"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/ns/"+key, bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("set %s: got %d", key, w.Code)
		}
	}

	// List
	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv/ns", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var listResp listResponse
	decodeJSON(t, w.Body, &listResp)
	if len(listResp.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(listResp.Keys))
	}

	// Delete
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/kv/ns/key1", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status: got %d, want %d", w.Code, http.StatusOK)
	}

	// List again
	req = httptest.NewRequest(http.MethodGet, "/api/v1/kv/ns", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	decodeJSON(t, w.Body, &listResp)
	if len(listResp.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listResp.Keys))
	}
}

func TestListNamespaces(t *testing.T) {
	_, mux := testServer(t)

	for _, ns := range []string{"alpha", "beta"} {
		body := `{"value":"v"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/"+ns+"/key", bytes.NewBufferString(body))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/kv", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp namespacesResponse
	decodeJSON(t, w.Body, &resp)
	if len(resp.Namespaces) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(resp.Namespaces))
	}
}

func TestSetInvalidBody(t *testing.T) {
	_, mux := testServer(t)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/kv/ns/key", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}
