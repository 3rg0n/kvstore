package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
)

// VerifyMode determines how an app's binary identity is verified.
type VerifyMode string

const (
	VerifyHash      VerifyMode = "hash"      // SHA-256 of binary
	VerifySignature VerifyMode = "signature" // Code signing identity
	VerifyAuto      VerifyMode = "auto"      // Auto-detect (resolved at registration)
)

var (
	ErrAppNotFound     = errors.New("app not found")
	ErrInvalidToken    = errors.New("invalid or unknown token")
	ErrBinaryMismatch  = errors.New("binary verification failed")
	ErrNamespaceDenied = errors.New("namespace access denied")
	ErrBinaryNotFound  = errors.New("binary not found or not accessible")
	ErrNotHashMode     = errors.New("rehash is only available for hash-mode apps")
)

// AppRecord represents a registered application with its access permissions.
type AppRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	BinaryPath string     `json:"binary_path"`
	VerifyMode VerifyMode `json:"verify_mode"`
	BinaryHash string     `json:"binary_hash"`
	SignerID   string     `json:"signer_id"`
	TokenHash  string     `json:"token_hash"`
	Namespaces []string   `json:"namespaces"`
	CreatedAt  time.Time  `json:"created_at"`
}

// AppStore defines the storage interface used by the Registry.
type AppStore interface {
	PutAppRecord(id string, data []byte) error
	GetAppRecord(id string) ([]byte, error)
	DeleteAppRecord(id string) error
	ListAppRecords() (map[string][]byte, error)
}

// Registry manages app registrations and verifies access.
type Registry struct {
	store AppStore
}

// NewRegistry creates a Registry backed by the given store.
func NewRegistry(store AppStore) *Registry {
	return &Registry{store: store}
}

// Register registers a new app and returns a one-time-visible token.
// The mode parameter supports VerifyAuto which resolves to hash or signature.
func (r *Registry) Register(name, binaryPath string, namespaces []string, mode VerifyMode) (string, error) {
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return "", fmt.Errorf("resolving binary path: %w", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return "", ErrBinaryNotFound
	}

	// Resolve auto mode
	if mode == VerifyAuto {
		_, signed, err := CheckSignature(absPath)
		if err != nil {
			return "", fmt.Errorf("checking binary signature: %w", err)
		}
		if signed {
			mode = VerifySignature
		} else {
			mode = VerifyHash
		}
	}

	record := AppRecord{
		ID:         uuid.New().String(),
		Name:       name,
		BinaryPath: absPath,
		VerifyMode: mode,
		Namespaces: namespaces,
		CreatedAt:  time.Now().UTC(),
	}

	if name == "" {
		record.Name = filepath.Base(absPath)
	}

	switch mode {
	case VerifyHash:
		hash, err := HashBinary(absPath)
		if err != nil {
			return "", fmt.Errorf("hashing binary: %w", err)
		}
		record.BinaryHash = hash
	case VerifySignature:
		signerID, signed, err := CheckSignature(absPath)
		if err != nil {
			return "", fmt.Errorf("checking signature: %w", err)
		}
		if !signed {
			return "", errors.New("binary is not code-signed; use --verify hash instead")
		}
		record.SignerID = signerID
	}

	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("generating token: %w", err)
	}
	record.TokenHash = hashToken(token)

	data, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("marshaling app record: %w", err)
	}

	if err := r.store.PutAppRecord(record.ID, data); err != nil {
		return "", fmt.Errorf("storing app record: %w", err)
	}

	return token, nil
}

// Revoke removes an app registration.
func (r *Registry) Revoke(appID string) error {
	if err := r.store.DeleteAppRecord(appID); err != nil {
		return fmt.Errorf("revoking app: %w", err)
	}
	return nil
}

// Rehash re-computes the binary hash for a hash-mode app after an update.
func (r *Registry) Rehash(appID string) error {
	record, err := r.getRecord(appID)
	if err != nil {
		return err
	}

	if record.VerifyMode != VerifyHash {
		return ErrNotHashMode
	}

	hash, err := HashBinary(record.BinaryPath)
	if err != nil {
		return fmt.Errorf("hashing binary: %w", err)
	}

	record.BinaryHash = hash
	return r.putRecord(record)
}

// UpdateNamespaces changes the allowed namespaces for an app.
func (r *Registry) UpdateNamespaces(appID string, namespaces []string) error {
	record, err := r.getRecord(appID)
	if err != nil {
		return err
	}

	record.Namespaces = namespaces
	return r.putRecord(record)
}

// List returns all registered app records.
func (r *Registry) List() ([]AppRecord, error) {
	rawRecords, err := r.store.ListAppRecords()
	if err != nil {
		return nil, fmt.Errorf("listing apps: %w", err)
	}

	records := make([]AppRecord, 0, len(rawRecords))
	for _, data := range rawRecords {
		var rec AppRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, fmt.Errorf("unmarshaling app record: %w", err)
		}
		records = append(records, rec)
	}
	return records, nil
}

// Verify validates a token against a calling binary and namespace.
// If binaryPath is empty, binary identity verification is skipped (used when
// process attestation is not yet available, e.g. over TCP before Step 3).
// Returns the matched AppRecord or an error describing the failure.
func (r *Registry) Verify(token, binaryPath, namespace string) (*AppRecord, error) {
	tHash := hashToken(token)

	rawRecords, err := r.store.ListAppRecords()
	if err != nil {
		return nil, fmt.Errorf("listing apps for verification: %w", err)
	}

	// Find the app record matching this token
	var matched *AppRecord
	for _, data := range rawRecords {
		var rec AppRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(rec.TokenHash), []byte(tHash)) == 1 {
			matched = &rec
			break
		}
	}
	if matched == nil {
		return nil, ErrInvalidToken
	}

	// Verify binary identity (skipped when binaryPath is empty)
	if binaryPath != "" {
		switch matched.VerifyMode {
		case VerifyHash:
			hash, err := HashBinary(binaryPath)
			if err != nil {
				return nil, fmt.Errorf("hashing caller binary: %w", err)
			}
			if subtle.ConstantTimeCompare([]byte(hash), []byte(matched.BinaryHash)) != 1 {
				return nil, ErrBinaryMismatch
			}
		case VerifySignature:
			signerID, signed, err := CheckSignature(binaryPath)
			if err != nil {
				return nil, fmt.Errorf("checking caller signature: %w", err)
			}
			if !signed || subtle.ConstantTimeCompare([]byte(signerID), []byte(matched.SignerID)) != 1 {
				return nil, ErrBinaryMismatch
			}
		}
	}

	// Check namespace ACL (skipped when namespace is empty, e.g. list-namespaces)
	if namespace != "" && !namespaceAllowed(matched.Namespaces, namespace) {
		return nil, ErrNamespaceDenied
	}

	return matched, nil
}

func (r *Registry) getRecord(appID string) (*AppRecord, error) {
	data, err := r.store.GetAppRecord(appID)
	if err != nil {
		return nil, ErrAppNotFound
	}
	var rec AppRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("unmarshaling app record: %w", err)
	}
	return &rec, nil
}

func (r *Registry) putRecord(rec *AppRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshaling app record: %w", err)
	}
	return r.store.PutAppRecord(rec.ID, data)
}

// HashBinary computes the SHA-256 hash of a file at the given path.
func HashBinary(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path)) //nolint:gosec // path is cleaned
	if err != nil {
		return "", fmt.Errorf("opening binary: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckSignature checks if a binary is code-signed and returns the signer identity.
// On macOS, uses the codesign tool. On Windows, uses Get-AuthenticodeSignature.
// On Linux, returns unsigned (no standard code signing mechanism).
func CheckSignature(path string) (signerID string, signed bool, err error) {
	switch runtime.GOOS {
	case "darwin":
		return checkSignatureDarwin(path)
	case "windows":
		return checkSignatureWindows(path)
	default:
		return "", false, nil
	}
}

// checkSignatureDarwin verifies an Apple code signature using the codesign tool
// and extracts the signing authority (e.g., "Developer ID Application: ...").
func checkSignatureDarwin(path string) (string, bool, error) {
	cmd := exec.Command("codesign", "-d", "-vvv", path) //nolint:gosec // path is caller-supplied binary path for signature verification
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", false, nil // unsigned or invalid
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authority=") {
			return strings.TrimPrefix(line, "Authority="), true, nil
		}
	}
	return "", false, nil
}

// checkSignatureWindows verifies an Authenticode signature and extracts the signer subject.
func checkSignatureWindows(path string) (string, bool, error) {
	script := `$sig = Get-AuthenticodeSignature -LiteralPath $env:KVSTORE_SIG_PATH
if ($sig.Status -eq 'Valid' -or $sig.Status -eq 'UnknownError') {
    Write-Output $sig.SignerCertificate.Subject
} else { exit 1 }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "KVSTORE_SIG_PATH="+path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", false, nil // unsigned
	}
	subject := strings.TrimSpace(string(output))
	if subject == "" {
		return "", false, nil
	}
	return subject, true, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return "kvs_" + hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func namespaceAllowed(allowed []string, namespace string) bool {
	for _, ns := range allowed {
		if ns == "*" || ns == namespace {
			return true
		}
	}
	return false
}
