//go:build !windows

package pki

import (
	"net"

	"github.com/ecopelan/kvstore/internal/platform"
)

func newTestPlatform() platform.Platform {
	return platform.New()
}

func dialPipe(addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}
