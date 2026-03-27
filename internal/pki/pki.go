// Package pki manages the per-installation PKI for mTLS IPC:
// CA generation, server/client cert lifecycle, and key encryption.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ecopelan/kvstore/internal/config"
	"github.com/ecopelan/kvstore/internal/crypto"
	"golang.org/x/crypto/hkdf"
)

const (
	caValidityYears         = 10
	serverCertValidityDays  = 7
	clientCertValidityYears = 1

	// clockSkewMargin handles minor clock drift on local certs.
	clockSkewMargin = 5 * time.Minute

	// rotationThreshold triggers server cert rotation when remaining
	// validity drops below this fraction of total lifetime.
	rotationThreshold = 24 * time.Hour

	pkiStoreKeyCAKey  = "ca-key"
	pkiStoreKeyCACert = "ca-cert"

	hkdfInfo = "kvstore-client-key"
)

// PKIStore abstracts encrypted storage for CA key material.
// Implemented by *store.Store via the _pki bbolt bucket.
type PKIStore interface {
	PutPKIData(key string, data []byte) error
	GetPKIData(key string) ([]byte, error)
}

// RegistryCertGenerator adapts the pki package functions to the
// auth.PKICertGenerator interface, binding a PKIStore and data directory.
type RegistryCertGenerator struct {
	store   PKIStore
	dataDir string
}

// NewRegistryCertGenerator creates a RegistryCertGenerator.
func NewRegistryCertGenerator(store PKIStore, dataDir string) *RegistryCertGenerator {
	return &RegistryCertGenerator{store: store, dataDir: dataDir}
}

// GenerateClientCert generates a client cert for the given app.
func (g *RegistryCertGenerator) GenerateClientCert(appID, appToken string) (string, string, error) {
	return GenerateClientCert(g.store, g.dataDir, appID, appToken)
}

// RevokeClientCert removes a client's certificate files.
func (g *RegistryCertGenerator) RevokeClientCert(appID string) error {
	return RevokeClientCert(appID)
}

// EnsureCA checks if a CA exists; if not, generates and stores one.
// The CA private key is stored encrypted in the store's _pki bucket.
// The CA certificate is written to {DataDir}/pki/ca.crt (public, distributable).
func EnsureCA(store PKIStore, dataDir string) error {
	// Check if CA key already exists in the store.
	_, err := store.GetPKIData(pkiStoreKeyCAKey)
	if err == nil {
		// CA key exists. Ensure cert file is also present.
		caPath := config.CAPath()
		if _, statErr := os.Stat(caPath); statErr == nil {
			return nil // CA fully set up
		}
		// CA key in store but cert file missing — regenerate cert file from stored cert PEM.
		certPEM, certErr := store.GetPKIData(pkiStoreKeyCACert)
		if certErr == nil {
			if mkErr := config.EnsurePKIDir(); mkErr != nil {
				return fmt.Errorf("creating pki dir: %w", mkErr)
			}
			return os.WriteFile(caPath, certPEM, 0644) //nolint:gosec // CA cert is public
		}
		// Cert PEM not in store either — fall through to regenerate everything.
	}

	// Generate new CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "kvstore-ca-" + shortID(),
			Organization: []string{"kvstore"},
		},
		NotBefore:             now.Add(-clockSkewMargin),
		NotAfter:              now.AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("marshaling CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Store CA key (encrypted by the store's master key).
	if err := store.PutPKIData(pkiStoreKeyCAKey, keyPEM); err != nil {
		return fmt.Errorf("storing CA key: %w", err)
	}

	// Store CA cert PEM in store (for recovery if file is deleted).
	if err := store.PutPKIData(pkiStoreKeyCACert, certPEM); err != nil {
		return fmt.Errorf("storing CA cert: %w", err)
	}

	// Write CA cert to file (public, readable by clients).
	if err := config.EnsurePKIDir(); err != nil {
		return fmt.Errorf("creating pki dir: %w", err)
	}
	if err := os.WriteFile(config.CAPath(), certPEM, 0644); err != nil { //nolint:gosec // CA cert is public
		return fmt.Errorf("writing CA cert: %w", err)
	}

	return nil
}

// NewServerTLSConfig creates a tls.Config for the kvstore server with mTLS.
// The server key is ephemeral (generated in memory, never persisted).
// The server cert is short-lived and auto-rotated via GetCertificate.
func NewServerTLSConfig(store PKIStore, dataDir string) (*tls.Config, error) {
	caCert, caKey, err := loadCA(store, dataDir)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}

	// Generate initial server cert.
	serverCert, err := generateServerCert(caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("generating server cert: %w", err)
	}

	// Build CA cert pool for client verification.
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	rotator := &certRotator{
		store:   store,
		dataDir: dataDir,
		current: serverCert,
	}

	return &tls.Config{
		GetCertificate: rotator.getCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
		// Prefer hybrid post-quantum key exchange (ML-KEM + classical).
		// Signatures remain ECDSA P-256 until Go stdlib adds ML-DSA to x509/tls.
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,    // hybrid: X25519 + ML-KEM-768
			tls.SecP256r1MLKEM768, // hybrid: P-256 + ML-KEM-768
			tls.X25519,            // classical fallback
			tls.CurveP256,         // classical fallback
		},
	}, nil
}

// GenerateClientCert generates a client certificate and encrypted private key
// for a registered app. The key is encrypted with HKDF(appToken).
// Returns the cert and key file paths.
func GenerateClientCert(store PKIStore, dataDir, appID, appToken string) (certPath, keyPath string, err error) {
	caCert, caKey, err := loadCA(store, dataDir)
	if err != nil {
		return "", "", fmt.Errorf("loading CA: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating client key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "kvstore-app-" + appID,
			Organization: []string{"kvstore"},
		},
		NotBefore:   now.Add(-clockSkewMargin),
		NotAfter:    now.AddDate(clientCertValidityYears, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("creating client cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		return "", "", fmt.Errorf("marshaling client key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Encrypt client key with HKDF-derived key from the app token.
	encKey := deriveClientKeyEncryptionKey(appToken, appID)
	encryptedKey, err := crypto.Encrypt(encKey, keyPEM)
	if err != nil {
		return "", "", fmt.Errorf("encrypting client key: %w", err)
	}

	if err := config.EnsurePKIDir(); err != nil {
		return "", "", fmt.Errorf("creating pki dir: %w", err)
	}

	certPath = config.ClientCertPath(appID)
	keyPath = config.ClientKeyPath(appID)

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", fmt.Errorf("writing client cert: %w", err)
	}
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		return "", "", fmt.Errorf("writing client key: %w", err)
	}

	return certPath, keyPath, nil
}

// LoadClientCert loads and decrypts a client certificate and private key.
// The key is decrypted using the app token via HKDF.
// This is primarily for testing and reference client implementations.
func LoadClientCert(appID, appToken string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(config.ClientCertPath(appID))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading client cert: %w", err)
	}

	encryptedKey, err := os.ReadFile(config.ClientKeyPath(appID))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading encrypted client key: %w", err)
	}

	encKey := deriveClientKeyEncryptionKey(appToken, appID)
	keyPEM, err := crypto.Decrypt(encKey, encryptedKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decrypting client key: %w", err)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// RevokeClientCert removes a client's certificate and key files.
// Returns nil if files don't exist (already revoked or never created).
func RevokeClientCert(appID string) error {
	var errs []error
	if err := os.Remove(config.ClientCertPath(appID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("removing client cert: %w", err))
	}
	if err := os.Remove(config.ClientKeyPath(appID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("removing client key: %w", err))
	}
	return errors.Join(errs...)
}

// CAFingerprint returns the SHA-256 fingerprint of the CA certificate.
func CAFingerprint(dataDir string) (string, error) {
	certPEM, err := os.ReadFile(config.CAPath())
	if err != nil {
		return "", fmt.Errorf("reading CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("decoding CA cert PEM")
	}
	h := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(h[:]), nil
}

// --- internal helpers ---

// loadCA loads the CA certificate and private key from store and file.
func loadCA(store PKIStore, _ string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	keyPEM, err := store.GetPKIData(pkiStoreKeyCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("loading CA key from store: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("decoding CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA key: %w", err)
	}

	certPEM, err := os.ReadFile(config.CAPath())
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("decoding CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA cert: %w", err)
	}

	return caCert, caKey, nil
}

// generateServerCert creates a short-lived server certificate signed by the CA.
func generateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating server key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "kvstore-server-" + shortID(),
			Organization: []string{"kvstore"},
		},
		NotBefore:   now.Add(-clockSkewMargin),
		NotAfter:    now.AddDate(0, 0, serverCertValidityDays),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("creating TLS keypair: %w", err)
	}
	cert.Leaf, _ = x509.ParseCertificate(certDER)

	return &cert, nil
}

// certRotator manages automatic server certificate rotation.
type certRotator struct {
	store   PKIStore
	dataDir string
	mu      sync.RWMutex
	current *tls.Certificate
}

func (r *certRotator) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert := r.current
	r.mu.RUnlock()

	// Check if rotation is needed.
	if cert.Leaf != nil && time.Until(cert.Leaf.NotAfter) < rotationThreshold {
		if newCert, err := r.rotate(); err == nil {
			return newCert, nil
		}
		// Rotation failed — use existing cert (still valid, just close to expiry).
	}

	return cert, nil
}

func (r *certRotator) rotate() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock.
	if r.current.Leaf != nil && time.Until(r.current.Leaf.NotAfter) >= rotationThreshold {
		return r.current, nil
	}

	caCert, caKey, err := loadCA(r.store, r.dataDir)
	if err != nil {
		return nil, fmt.Errorf("loading CA for rotation: %w", err)
	}

	cert, err := generateServerCert(caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("generating rotated cert: %w", err)
	}

	r.current = cert
	return cert, nil
}

// deriveClientKeyEncryptionKey derives a 32-byte AES key from the app token
// using HKDF-SHA256 with the appID as salt.
func deriveClientKeyEncryptionKey(appToken, appID string) []byte {
	h := hkdf.New(sha256.New, []byte(appToken), []byte(appID), []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("hkdf: " + err.Error()) // should never happen with valid inputs
	}
	return key
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	return serial, nil
}

func shortID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
