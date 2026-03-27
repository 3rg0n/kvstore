//go:build windows

package pki

import (
	"net"

	winio "github.com/Microsoft/go-winio"
	"github.com/ecopelan/kvstore/internal/platform"
)

// newTestPlatform returns a platform.Platform for the current OS.
func newTestPlatform() platform.Platform {
	return platform.New()
}

// dialPipe connects to a named pipe by address string.
func dialPipe(addr string) (net.Conn, error) {
	return winio.DialPipe(addr, nil)
}
