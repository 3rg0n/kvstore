package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ecopelan/kvstore/internal/store"
)

func setupTestRegistry(t *testing.T) (*Registry, *store.Store) {
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
	return NewRegistry(s), s
}

// testBinaryPath returns the path to the current test binary, which is a real
// file we can hash for testing purposes.
func testBinaryPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("getting test executable: %v", err)
	}
	return exe
}

func TestRegisterAndList(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"ns1", "ns2"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if len(token) < 10 || token[:4] != "kvs_" {
		t.Fatalf("unexpected token format: %s", token)
	}

	apps, err := reg.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}
	if apps[0].Name != "test-app" {
		t.Errorf("expected name 'test-app', got %q", apps[0].Name)
	}
	if apps[0].VerifyMode != VerifyHash {
		t.Errorf("expected verify mode 'hash', got %q", apps[0].VerifyMode)
	}
	if apps[0].BinaryHash == "" {
		t.Error("expected non-empty binary hash")
	}
	if len(apps[0].Namespaces) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(apps[0].Namespaces))
	}
}

func TestRegisterAutoMode(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	// Auto resolves to hash when the test binary is unsigned
	token, err := reg.Register("", binary, []string{"ns1"}, VerifyAuto)
	if err != nil {
		t.Fatalf("register auto: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	apps, err := reg.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if apps[0].VerifyMode != VerifyHash {
		t.Errorf("auto should resolve to hash, got %q", apps[0].VerifyMode)
	}
	// Name should default to binary filename
	if apps[0].Name == "" {
		t.Error("expected non-empty default name")
	}
}

func TestRegisterBinaryNotFound(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	_, err := reg.Register("bad", "/nonexistent/binary", []string{"ns1"}, VerifyHash)
	if err != ErrBinaryNotFound {
		t.Fatalf("expected ErrBinaryNotFound, got %v", err)
	}
}

func TestVerifySuccess(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rec, err := reg.Verify(token, binary, 0, "secrets")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rec.Name != "test-app" {
		t.Errorf("expected name 'test-app', got %q", rec.Name)
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	_, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = reg.Verify("kvs_bogustoken", binary, 0, "secrets")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerifyBinaryMismatch(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Create a different binary to trigger mismatch
	tmp := filepath.Join(t.TempDir(), "fake.exe")
	if err := os.WriteFile(tmp, []byte("not the real binary"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = reg.Verify(token, tmp, 0, "secrets")
	if err != ErrBinaryMismatch {
		t.Fatalf("expected ErrBinaryMismatch, got %v", err)
	}
}

func TestVerifyNamespaceDenied(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	_, err = reg.Verify(token, binary, 0, "other-namespace")
	if err != ErrNamespaceDenied {
		t.Fatalf("expected ErrNamespaceDenied, got %v", err)
	}
}

func TestVerifyWildcardNamespace(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("admin-app", binary, []string{"*"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	rec, err := reg.Verify(token, binary, 0, "any-namespace")
	if err != nil {
		t.Fatalf("verify wildcard: %v", err)
	}
	if rec.Name != "admin-app" {
		t.Errorf("expected name 'admin-app', got %q", rec.Name)
	}
}

func TestRevoke(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	apps, _ := reg.List()
	if len(apps) != 1 {
		t.Fatalf("expected 1 app, got %d", len(apps))
	}

	if err := reg.Revoke(apps[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	apps, _ = reg.List()
	if len(apps) != 0 {
		t.Fatalf("expected 0 apps after revoke, got %d", len(apps))
	}

	// Verify with old token should fail
	_, err = reg.Verify(token, binary, 0, "secrets")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken after revoke, got %v", err)
	}
}

func TestRehash(t *testing.T) {
	reg, _ := setupTestRegistry(t)

	// Create a mutable binary file
	dir := t.TempDir()
	binPath := filepath.Join(dir, "myapp.exe")
	if err := os.WriteFile(binPath, []byte("version-1"), 0600); err != nil {
		t.Fatal(err)
	}

	token, err := reg.Register("myapp", binPath, []string{"ns1"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Verify works with original binary
	_, err = reg.Verify(token, binPath, 0, "ns1")
	if err != nil {
		t.Fatalf("verify before update: %v", err)
	}

	// Simulate binary update
	if err := os.WriteFile(binPath, []byte("version-2"), 0600); err != nil {
		t.Fatal(err)
	}

	// Verify should fail now (hash mismatch)
	_, err = reg.Verify(token, binPath, 0, "ns1")
	if err != ErrBinaryMismatch {
		t.Fatalf("expected ErrBinaryMismatch after update, got %v", err)
	}

	// Rehash
	apps, _ := reg.List()
	if err := reg.Rehash(apps[0].ID); err != nil {
		t.Fatalf("rehash: %v", err)
	}

	// Verify should work again
	_, err = reg.Verify(token, binPath, 0, "ns1")
	if err != nil {
		t.Fatalf("verify after rehash: %v", err)
	}
}

func TestRehashSignatureModeError(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	// Register in hash mode first (signature mode requires a signed binary)
	_, err := reg.Register("test-app", binary, []string{"ns1"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	apps, _ := reg.List()

	// Manually change verify mode to test the guard
	rec, err := reg.getRecord(apps[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.VerifyMode = VerifySignature
	if err := reg.putRecord(rec); err != nil {
		t.Fatal(err)
	}

	err = reg.Rehash(apps[0].ID)
	if err != ErrNotHashMode {
		t.Fatalf("expected ErrNotHashMode, got %v", err)
	}
}

func TestUpdateNamespaces(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token, err := reg.Register("test-app", binary, []string{"ns1"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Can access ns1
	_, err = reg.Verify(token, binary, 0, "ns1")
	if err != nil {
		t.Fatalf("verify ns1: %v", err)
	}

	// Cannot access ns2
	_, err = reg.Verify(token, binary, 0, "ns2")
	if err != ErrNamespaceDenied {
		t.Fatalf("expected ErrNamespaceDenied for ns2, got %v", err)
	}

	// Update namespaces
	apps, _ := reg.List()
	if err := reg.UpdateNamespaces(apps[0].ID, []string{"ns2", "ns3"}); err != nil {
		t.Fatalf("update namespaces: %v", err)
	}

	// Now can access ns2
	_, err = reg.Verify(token, binary, 0, "ns2")
	if err != nil {
		t.Fatalf("verify ns2 after update: %v", err)
	}

	// But not ns1 anymore
	_, err = reg.Verify(token, binary, 0, "ns1")
	if err != ErrNamespaceDenied {
		t.Fatalf("expected ErrNamespaceDenied for ns1 after update, got %v", err)
	}
}

func TestMultipleApps(t *testing.T) {
	reg, _ := setupTestRegistry(t)
	binary := testBinaryPath(t)

	token1, err := reg.Register("app1", binary, []string{"ns1"}, VerifyHash)
	if err != nil {
		t.Fatalf("register app1: %v", err)
	}

	token2, err := reg.Register("app2", binary, []string{"ns2"}, VerifyHash)
	if err != nil {
		t.Fatalf("register app2: %v", err)
	}

	apps, _ := reg.List()
	if len(apps) != 2 {
		t.Fatalf("expected 2 apps, got %d", len(apps))
	}

	// app1 can access ns1 but not ns2
	_, err = reg.Verify(token1, binary, 0, "ns1")
	if err != nil {
		t.Fatalf("app1 access ns1: %v", err)
	}
	_, err = reg.Verify(token1, binary, 0, "ns2")
	if err != ErrNamespaceDenied {
		t.Fatalf("expected app1 denied ns2, got %v", err)
	}

	// app2 can access ns2 but not ns1
	_, err = reg.Verify(token2, binary, 0, "ns2")
	if err != nil {
		t.Fatalf("app2 access ns2: %v", err)
	}
	_, err = reg.Verify(token2, binary, 0, "ns1")
	if err != ErrNamespaceDenied {
		t.Fatalf("expected app2 denied ns1, got %v", err)
	}
}

func TestHashBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, []byte("hello world"), 0600); err != nil {
		t.Fatal(err)
	}

	hash1, err := HashBinary(path)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// Same content should produce same hash
	hash2, err := HashBinary(path)
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if hash1 != hash2 {
		t.Error("same file should produce same hash")
	}

	// Different content should produce different hash
	path2 := filepath.Join(dir, "test2.bin")
	if err := os.WriteFile(path2, []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	hash3, err := HashBinary(path2)
	if err != nil {
		t.Fatalf("hash3: %v", err)
	}
	if hash1 == hash3 {
		t.Error("different files should produce different hashes")
	}
}

func TestHashBinaryNotFound(t *testing.T) {
	_, err := HashBinary("/nonexistent/file")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestAppsExcludedFromNamespaces(t *testing.T) {
	reg, s := setupTestRegistry(t)
	binary := testBinaryPath(t)

	// Register an app (creates _apps bucket)
	_, err := reg.Register("test-app", binary, []string{"secrets"}, VerifyHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// Also create a regular namespace
	if err := s.Set("secrets", "key1", []byte("value1")); err != nil {
		t.Fatalf("set: %v", err)
	}

	// _apps should not appear in ListNamespaces
	namespaces, err := s.ListNamespaces()
	if err != nil {
		t.Fatalf("list namespaces: %v", err)
	}
	for _, ns := range namespaces {
		if ns == "_apps" {
			t.Error("_apps should not appear in namespace listing")
		}
	}
}
