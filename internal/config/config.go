package config

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	AppName     = "kvstore"
	DefaultAddr = "127.0.0.1:7390"
)

// DataDir returns the platform-specific data directory.
func DataDir() string {
	if dir := os.Getenv("KVSTORE_DATA_DIR"); dir != "" {
		return dir
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), AppName)
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", AppName)
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, AppName)
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".local", "share", AppName)
	}
}

// StorePath returns the path to the store database file.
func StorePath() string {
	return filepath.Join(DataDir(), "store.db")
}

// SocketPath returns the platform-specific IPC socket/pipe path.
func SocketPath() string {
	switch runtime.GOOS {
	case "windows":
		return AppName // becomes \\.\pipe\kvstore
	case "linux":
		if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
			return filepath.Join(xdg, AppName+".sock")
		}
		return filepath.Join(DataDir(), AppName+".sock")
	default: // darwin
		return filepath.Join(DataDir(), AppName+".sock")
	}
}

// EnsureDataDir creates the data directory if it doesn't exist.
func EnsureDataDir() error {
	return os.MkdirAll(DataDir(), 0700)
}

// PKIDir returns the path to the PKI directory.
func PKIDir() string {
	return filepath.Join(DataDir(), "pki")
}

// CAPath returns the path to the CA certificate (PEM, public).
func CAPath() string {
	return filepath.Join(PKIDir(), "ca.crt")
}

// ClientCertsDir returns the path to the client certificates directory.
func ClientCertsDir() string {
	return filepath.Join(PKIDir(), "clients")
}

// ClientCertPath returns the path to a client certificate.
func ClientCertPath(appID string) string {
	return filepath.Join(ClientCertsDir(), appID+".crt")
}

// ClientKeyPath returns the path to an encrypted client private key.
func ClientKeyPath(appID string) string {
	return filepath.Join(ClientCertsDir(), appID+".key.enc")
}

// EnsurePKIDir creates the PKI directories if they don't exist.
func EnsurePKIDir() error {
	return os.MkdirAll(ClientCertsDir(), 0700)
}
