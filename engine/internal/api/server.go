// Package api exposes the scanning engine over HTTP. It is deliberately thin:
// parse and guard the request, delegate to the engine, serialize the result.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/config"
	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// Server wires together configuration, the SSRF guard, and the scan engine.
type Server struct {
	cfg     config.Config
	guard   *netutil.Guard
	engine  *scan.Engine
	started time.Time
}

// NewServer constructs a Server from configuration.
func NewServer(cfg config.Config) *Server {
	return &Server{
		cfg:   cfg,
		guard: netutil.NewGuard(cfg.AllowPrivate),
		engine: scan.NewEngine(scan.Options{
			MaxConcurrency: cfg.MaxConcurrency,
			ModuleTimeout:  cfg.ModuleTimeout,
			ScanTimeout:    cfg.ScanTimeout,
		}),
		started: time.Now(),
	}
}

// Handler returns the fully-wrapped HTTP handler (routes + middleware).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /v1/modules", s.handleModules)
	mux.HandleFunc("POST /v1/scan", s.handleScan)
	mux.HandleFunc("GET /v1/scan", s.handleScan) // convenience for ?target=

	chain := s.withCORS(s.withRateLimit(s.withRecover(mux)))
	return s.withLogging(chain)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
