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
		Name:        "kvstoremon",
		DisplayName: "kvstoremon",
		Description: "Lightweight encrypted key-value store service",
		Executable:  exe,
		Arguments:   []string{"serve"},
	}

	return service.New(&stub{}, cfg)
}

type stub struct{}

func (s *stub) Start(_ service.Service) error { return nil }
func (s *stub) Stop(_ service.Service) error  { return nil }
