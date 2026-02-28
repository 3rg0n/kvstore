package store

import (
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Init([]byte("test-password-123")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInitAndUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if s.IsInitialized() {
		t.Fatal("new store should not be initialized")
	}

	if err := s.Init([]byte("my-password")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if !s.IsInitialized() {
		t.Fatal("store should be initialized after Init")
	}
	_ = s.Close()

	// Reopen and unlock
	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Unlock([]byte("wrong-password")); err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got: %v", err)
	}

	if err := s.Unlock([]byte("my-password")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestDoubleInit(t *testing.T) {
	s := testStore(t)
	if err := s.Init([]byte("another")); err != ErrAlreadyInit {
		t.Fatalf("expected ErrAlreadyInit, got: %v", err)
	}
}

func TestSetGetDelete(t *testing.T) {
	s := testStore(t)

	if err := s.Set("secrets", "api-key", []byte("sk-12345")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entry, err := s.Get("secrets", "api-key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(entry.Value) != "sk-12345" {
		t.Fatalf("got %q, want %q", entry.Value, "sk-12345")
	}

	// Update
	if err := s.Set("secrets", "api-key", []byte("sk-67890")); err != nil {
		t.Fatalf("Set update: %v", err)
	}

	entry, err = s.Get("secrets", "api-key")
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if string(entry.Value) != "sk-67890" {
		t.Fatalf("got %q, want %q", entry.Value, "sk-67890")
	}

	// Delete
	if err := s.Delete("secrets", "api-key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Get("secrets", "api-key")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestDeleteNotFound(t *testing.T) {
	s := testStore(t)

	if err := s.Delete("ns", "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestGetNotFound(t *testing.T) {
	s := testStore(t)

	_, err := s.Get("ns", "missing")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestList(t *testing.T) {
	s := testStore(t)

	_ = s.Set("ns1", "key1", []byte("v1"))
	_ = s.Set("ns1", "key2", []byte("v2"))
	_ = s.Set("ns2", "key3", []byte("v3"))

	keys, err := s.List("ns1")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	// Empty namespace returns nil, no error
	keys, err = s.List("nonexistent")
	if err != nil {
		t.Fatalf("List empty: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestListNamespaces(t *testing.T) {
	s := testStore(t)

	_ = s.Set("alpha", "k", []byte("v"))
	_ = s.Set("beta", "k", []byte("v"))

	ns, err := s.ListNamespaces()
	if err != nil {
		t.Fatalf("ListNamespaces: %v", err)
	}
	if len(ns) != 2 {
		t.Fatalf("expected 2 namespaces, got %d", len(ns))
	}
}

func TestSetPreservesCreatedAt(t *testing.T) {
	s := testStore(t)

	_ = s.Set("ns", "key", []byte("v1"))
	e1, _ := s.Get("ns", "key")

	time.Sleep(10 * time.Millisecond)

	_ = s.Set("ns", "key", []byte("v2"))
	e2, _ := s.Get("ns", "key")

	if !e1.CreatedAt.Equal(e2.CreatedAt) {
		t.Fatal("created_at should be preserved on update")
	}
	if !e2.UpdatedAt.After(e1.UpdatedAt) {
		t.Fatal("updated_at should change on update")
	}
}

func TestNotInitialized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	_, err = s.Get("ns", "key")
	if err != ErrNotInitialized {
		t.Fatalf("expected ErrNotInitialized, got: %v", err)
	}

	if err := s.Set("ns", "key", []byte("v")); err != ErrNotInitialized {
		t.Fatalf("expected ErrNotInitialized for Set, got: %v", err)
	}
}
