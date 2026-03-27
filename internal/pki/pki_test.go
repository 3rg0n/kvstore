package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ecopelan/kvstore/internal/config"
	"github.com/ecopelan/kvstore/internal/store"
)

func setupTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Init([]byte("testpassword")); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func withTestDataDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KVSTORE_DATA_DIR", dir)
}

func TestEnsureCA(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	// First call: generates CA.
	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	// Verify CA cert file exists.
	caPath := config.CAPath()
	certPEM, err := os.ReadFile(caPath) //nolint:gosec // test file path from config
	if err != nil {
		t.Fatalf("reading CA cert: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}

	if !cert.IsCA {
		t.Error("CA cert IsCA is false")
	}
	if cert.MaxPathLen != 0 {
		t.Errorf("MaxPathLen = %d, want 0", cert.MaxPathLen)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("algorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
	}

	// Verify CA key is stored in store.
	keyPEM, err := s.GetPKIData(pkiStoreKeyCAKey)
	if err != nil {
		t.Fatalf("GetPKIData(ca-key): %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("failed to decode CA key PEM from store")
	}
	_, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parsing CA key from store: %v", err)
	}
}

func TestEnsureCA_Idempotent(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}

	// Read the CA cert.
	cert1, err := os.ReadFile(config.CAPath())
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}

	// Second call should be a no-op.
	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}

	cert2, err := os.ReadFile(config.CAPath())
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}

	if string(cert1) != string(cert2) {
		t.Error("EnsureCA regenerated the CA cert on second call")
	}
}

func TestEnsureCA_RecoversCertFile(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	// Delete the cert file.
	if err := os.Remove(config.CAPath()); err != nil {
		t.Fatalf("removing CA cert: %v", err)
	}

	// EnsureCA should recover the cert from the store.
	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA after delete: %v", err)
	}

	if _, err := os.Stat(config.CAPath()); err != nil {
		t.Fatalf("CA cert not recovered: %v", err)
	}
}

func TestNewServerTLSConfig(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	tlsConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3 (%d)", tlsConfig.MinVersion, tls.VersionTLS13)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tlsConfig.ClientAuth)
	}
	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate is nil")
	}

	// GetCertificate should return a valid cert.
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("cert.Leaf is nil")
	}
	if cert.Leaf.Subject.CommonName == "" {
		t.Error("server cert CN is empty")
	}
}

func TestGenerateClientCert(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	appID := "test-app-id"
	appToken := "kvs_testtoken1234567890"

	certPath, keyPath, err := GenerateClientCert(s, config.DataDir(), appID, appToken)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Verify files exist.
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert file missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file missing: %v", err)
	}

	// Verify cert is valid.
	certPEM, err := os.ReadFile(certPath) //nolint:gosec // test file path from config
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("decode cert PEM failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing client cert: %v", err)
	}
	if cert.Subject.CommonName != "kvstore-app-"+appID {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "kvstore-app-"+appID)
	}
	if len(cert.ExtKeyUsage) == 0 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("missing ExtKeyUsageClientAuth")
	}
}

func TestLoadClientCert(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	appID := "test-load"
	appToken := "kvs_loadtoken12345"

	if _, _, err := GenerateClientCert(s, config.DataDir(), appID, appToken); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Load with correct token — should succeed.
	cert, err := LoadClientCert(appID, appToken)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("loaded cert has no certificates")
	}

	// Load with wrong token — should fail.
	_, err = LoadClientCert(appID, "kvs_wrongtoken")
	if err == nil {
		t.Error("LoadClientCert with wrong token should fail")
	}
}

func TestRevokeClientCert(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	appID := "test-revoke"
	appToken := "kvs_revoketoken"

	certPath, keyPath, err := GenerateClientCert(s, config.DataDir(), appID, appToken)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	if err := RevokeClientCert(appID); err != nil {
		t.Fatalf("RevokeClientCert: %v", err)
	}

	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Error("cert file still exists after revocation")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Error("key file still exists after revocation")
	}

	// Revoking again should not error.
	if err := RevokeClientCert(appID); err != nil {
		t.Fatalf("double revoke: %v", err)
	}
}

func TestMTLSHandshake(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	// Create server TLS config.
	serverConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	// Start TLS listener on random port.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Generate client cert.
	appID := "handshake-test"
	appToken := "kvs_handshaketoken"
	if _, _, err := GenerateClientCert(s, config.DataDir(), appID, appToken); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Load client cert.
	clientCert, err := LoadClientCert(appID, appToken)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}

	// Build client TLS config.
	caCertPEM, err := os.ReadFile(config.CAPath())
	if err != nil {
		t.Fatalf("reading CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	// Server goroutine: accept one connection.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}

		// Verify client cert CN.
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			serverDone <- fmt.Errorf("no client certificates")
			return
		}
		cn := state.PeerCertificates[0].Subject.CommonName
		if cn != "kvstore-app-"+appID {
			serverDone <- fmt.Errorf("client CN = %q, want %q", cn, "kvstore-app-"+appID)
			return
		}

		_, _ = conn.Write([]byte("OK"))
		serverDone <- nil
	}()

	// Client: connect and handshake.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read from server: %v", err)
	}
	if string(buf) != "OK" {
		t.Errorf("server response = %q, want %q", buf, "OK")
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestMTLSHandshake_NoClientCert(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	serverConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Server: accept and try handshake.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		err = conn.(*tls.Conn).Handshake()
		serverDone <- err
	}()

	// Client without client cert — should fail handshake.
	caCertPEM, _ := os.ReadFile(config.CAPath())
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientConfig := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	}

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tlsConn := tls.Client(conn, clientConfig)
	err = tlsConn.Handshake()
	_ = tlsConn.Close()

	// Either client or server should report a handshake error.
	if err == nil {
		serverErr := <-serverDone
		if serverErr == nil {
			t.Fatal("expected handshake failure without client cert")
		}
	}
}

func TestMTLSHandshake_WrongCA(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	serverConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	// Generate a rogue CA and client cert.
	rogueKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rogueTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rogue-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rogueCertDER, _ := x509.CreateCertificate(rand.Reader, rogueTemplate, rogueTemplate, &rogueKey.PublicKey, rogueKey)
	rogueCert, _ := x509.ParseCertificate(rogueCertDER)

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "rogue-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, _ := x509.CreateCertificate(rand.Reader, clientTemplate, rogueCert, &clientKey.PublicKey, rogueKey)

	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyDER, _ := x509.MarshalECPrivateKey(clientKey)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyDER})
	tlsCert, _ := tls.X509KeyPair(clientCertPEM, clientKeyPEM)

	roguePool := x509.NewCertPool()
	roguePool.AddCert(rogueCert)

	clientConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		RootCAs:            roguePool,
		ServerName:         "localhost",
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // intentionally skip server verify to test client cert rejection
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected handshake failure with rogue CA client cert")
	}
}

func TestCAFingerprint(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	fp, err := CAFingerprint(config.DataDir())
	if err != nil {
		t.Fatalf("CAFingerprint: %v", err)
	}
	if len(fp) != 64 { // SHA-256 hex
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
}

func TestDeriveClientKeyEncryptionKey(t *testing.T) {
	key1 := deriveClientKeyEncryptionKey("token-a", "app-1")
	key2 := deriveClientKeyEncryptionKey("token-a", "app-2")
	key3 := deriveClientKeyEncryptionKey("token-b", "app-1")

	if string(key1) == string(key2) {
		t.Error("different appIDs should produce different keys")
	}
	if string(key1) == string(key3) {
		t.Error("different tokens should produce different keys")
	}
	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
}

func TestCertRotationConcurrent(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	caCert, caKey, err := loadCA(s, config.DataDir())
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}

	// Create a cert that's about to expire (within rotationThreshold).
	serverCert, err := generateServerCert(caCert, caKey)
	if err != nil {
		t.Fatalf("generateServerCert: %v", err)
	}
	// Patch Leaf.NotAfter to trigger rotation on next call.
	serverCert.Leaf.NotAfter = time.Now().Add(30 * time.Second)

	rotator := &certRotator{
		store:   s,
		dataDir: config.DataDir(),
		current: serverCert,
	}

	// Hammer getCertificate from multiple goroutines concurrently.
	const goroutines = 20
	const callsPerGoroutine = 50
	errs := make(chan error, goroutines*callsPerGoroutine)

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < callsPerGoroutine; j++ {
				cert, err := rotator.getCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					errs <- err
					return
				}
				if cert == nil || cert.Leaf == nil {
					errs <- fmt.Errorf("got nil cert or nil Leaf")
					return
				}
				errs <- nil
			}
		}()
	}

	for i := 0; i < goroutines*callsPerGoroutine; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent getCertificate: %v", err)
		}
	}

	// After rotation, the cert should have a new NotAfter well into the future.
	finalCert, err := rotator.getCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("final getCertificate: %v", err)
	}
	if time.Until(finalCert.Leaf.NotAfter) < rotationThreshold {
		t.Error("cert was not rotated — still within rotation threshold")
	}
}

func TestConnContextTLSUnwrap(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	serverConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	// Start TLS listener on TCP.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Generate client cert.
	appID := "connctx-test"
	appToken := "kvs_connctxtoken" //nolint:gosec // test token
	if _, _, err := GenerateClientCert(s, config.DataDir(), appID, appToken); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	clientCert, err := LoadClientCert(appID, appToken)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}

	caCertPEM, _ := os.ReadFile(config.CAPath()) //nolint:gosec // test file
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	// Server: accept connection, verify ConnContext unwraps TLS.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			serverDone <- fmt.Errorf("accepted conn is not *tls.Conn")
			return
		}

		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}

		// Simulate what ConnContext does — unwrap TLS to get underlying conn.
		underlying := tlsConn.NetConn()
		if underlying == nil {
			serverDone <- fmt.Errorf("NetConn() returned nil")
			return
		}

		// The underlying conn should be a *net.TCPConn, not a *tls.Conn.
		if _, isTLS := underlying.(*tls.Conn); isTLS {
			serverDone <- fmt.Errorf("NetConn() returned another *tls.Conn — unwrap failed")
			return
		}

		// Verify the underlying conn has a valid local address (proves it's a real conn).
		if underlying.LocalAddr() == nil {
			serverDone <- fmt.Errorf("underlying conn has nil LocalAddr")
			return
		}

		_, _ = conn.Write([]byte("OK"))
		serverDone <- nil
	}()

	// Client: connect.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestMTLSOverNamedPipe(t *testing.T) {
	withTestDataDir(t)
	s := setupTestStore(t)

	if err := EnsureCA(s, config.DataDir()); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}

	serverConfig, err := NewServerTLSConfig(s, config.DataDir())
	if err != nil {
		t.Fatalf("NewServerTLSConfig: %v", err)
	}

	// Create platform-native IPC listener.
	pipeName := fmt.Sprintf("kvstore-test-mtls-%s", shortID())
	plat := newTestPlatform()
	ipcLn, err := plat.Listener(pipeName)
	if err != nil {
		t.Fatalf("platform Listener: %v", err)
	}
	defer func() { _ = ipcLn.Close() }()

	// Wrap IPC listener with TLS — same as production code path.
	tlsLn := tls.NewListener(ipcLn, serverConfig)

	// Generate client cert.
	appID := "pipe-test"
	appToken := "kvs_pipetoken123"
	if _, _, err := GenerateClientCert(s, config.DataDir(), appID, appToken); err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	clientCert, err := LoadClientCert(appID, appToken)
	if err != nil {
		t.Fatalf("LoadClientCert: %v", err)
	}

	caCertPEM, _ := os.ReadFile(config.CAPath()) //nolint:gosec // test file
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	// Server goroutine.
	serverDone := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}

		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			serverDone <- fmt.Errorf("no client certs")
			return
		}
		cn := state.PeerCertificates[0].Subject.CommonName
		if cn != "kvstore-app-"+appID {
			serverDone <- fmt.Errorf("client CN = %q, want %q", cn, "kvstore-app-"+appID)
			return
		}

		_, _ = conn.Write([]byte("OK"))
		serverDone <- nil
	}()

	// Client: connect via named pipe with TLS.
	pipeAddr := ipcLn.Addr().String()
	rawConn, err := dialPipe(pipeAddr)
	if err != nil {
		t.Fatalf("dial pipe: %v", err)
	}

	tlsConn := tls.Client(rawConn, clientConfig)
	defer func() { _ = tlsConn.Close() }()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake over pipe: %v", err)
	}

	buf := make([]byte, 2)
	if _, err := tlsConn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "OK" {
		t.Errorf("response = %q, want %q", buf, "OK")
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}
