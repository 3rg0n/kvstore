package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ecopelan/kvstore/internal/auth"
	"github.com/ecopelan/kvstore/internal/store"
)

// Server is the HTTP API server for kvstore.
type Server struct {
	store  *store.Store
	logger *slog.Logger
	http   *http.Server
}

type errorResponse struct {
	Error string `json:"error"`
}

type kvResponse struct {
	Namespace string `json:"namespace"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type listResponse struct {
	Keys []string `json:"keys"`
}

type namespacesResponse struct {
	Namespaces []string `json:"namespaces"`
}

type setRequest struct {
	Value string `json:"value"`
}

// New creates a new HTTP API server. If authMw is non-nil, all KV routes
// require a valid app token. The health endpoint is always unauthenticated.
func New(s *store.Store, logger *slog.Logger, authMw *auth.Middleware) *Server {
	srv := &Server{
		store:  s,
		logger: logger,
	}

	// wrap optionally applies auth middleware when configured.
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		if authMw != nil {
			return authMw.RequireAuth(h)
		}
		return h
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/kv", wrap(srv.handleListNamespaces))
	mux.HandleFunc("GET /api/v1/kv/{namespace}", wrap(srv.handleList))
	mux.HandleFunc("GET /api/v1/kv/{namespace}/{key}", wrap(srv.handleGet))
	mux.HandleFunc("PUT /api/v1/kv/{namespace}/{key}", wrap(srv.handleSet))
	mux.HandleFunc("DELETE /api/v1/kv/{namespace}/{key}", wrap(srv.handleDelete))

	httpSrv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// When auth middleware is active, inject connections into request
	// context so the middleware can resolve caller PID → binary path.
	if authMw != nil {
		httpSrv.ConnContext = auth.ConnContext
	}

	srv.http = httpSrv
	return srv
}

// Start starts the HTTP server on the given listener.
func (s *Server) Start(ln net.Listener) error {
	s.logger.Info("server started", "addr", ln.Addr())
	return s.http.Serve(ln)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	key := r.PathValue("key")

	entry, err := s.store.Get(namespace, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "key not found"})
			return
		}
		s.logger.Error("get failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, kvResponse{
		Namespace: namespace,
		Key:       key,
		Value:     string(entry.Value),
		CreatedAt: entry.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
	})
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	key := r.PathValue("key")

	var req setRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	if err := s.store.Set(namespace, key, []byte(req.Value)); err != nil {
		s.logger.Error("set failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, kvResponse{
		Namespace: namespace,
		Key:       key,
		Value:     req.Value,
	})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")
	key := r.PathValue("key")

	if err := s.store.Delete(namespace, key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorResponse{Error: "key not found"})
			return
		}
		s.logger.Error("delete failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	namespace := r.PathValue("namespace")

	keys, err := s.store.List(namespace)
	if err != nil {
		s.logger.Error("list failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	if keys == nil {
		keys = []string{}
	}

	writeJSON(w, http.StatusOK, listResponse{Keys: keys})
}

func (s *Server) handleListNamespaces(w http.ResponseWriter, _ *http.Request) {
	namespaces, err := s.store.ListNamespaces()
	if err != nil {
		s.logger.Error("list namespaces failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	if namespaces == nil {
		namespaces = []string{}
	}

	writeJSON(w, http.StatusOK, namespacesResponse{Namespaces: namespaces})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
