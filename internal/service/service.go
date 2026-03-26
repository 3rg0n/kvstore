package service

import (
	"os"

	"github.com/kardianos/service"
)

// New creates a service.Service for management operations (install, uninstall, start, stop, status).
func New() (service.Service, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}

	cfg := &service.Config{
		Name:        "kvstore",
		DisplayName: "kvstore",
		Description: "Lightweight encrypted key-value store service",
		Executable:  exe,
		Arguments:   []string{"serve"},
	}

	return service.New(&noopProgram{}, cfg)
}

// noopProgram satisfies the service.Interface required by kardianos/service.New
// for management operations (install, uninstall, status). The real Start/Stop
// logic lives in serveProgram in cmd/kvstore/main.go.
type noopProgram struct{}

func (n *noopProgram) Start(_ service.Service) error { return nil }
func (n *noopProgram) Stop(_ service.Service) error  { return nil }
