// Package api exposes the scanning engine over HTTP. It is deliberately thin:
// parse and guard the request, delegate to the engine, serialize the result.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/abuse"
	"github.com/ariho-code/bastionscan/engine/internal/auth"
	"github.com/ariho-code/bastionscan/engine/internal/config"
	"github.com/ariho-code/bastionscan/engine/internal/metrics"
	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// Server wires together configuration, auth, the SSRF guard, and the engine.
type Server struct {
	cfg      config.Config
	guard    *netutil.Guard
	engine   *scan.Engine
	auth     *auth.Authenticator
	limiter  *rateLimiter
	cooldown *abuse.Cooldown
	metrics  *metrics.Metrics
	started  time.Time
}

// NewServer constructs a Server from configuration.
func NewServer(cfg config.Config) *Server {
	// In dev (AllowPrivate) the per-target cooldown is disabled so repeated
	// local scans aren't throttled.
	cooldownWindow := cfg.TargetCooldown
	if cfg.AllowPrivate {
		cooldownWindow = 0
	}
	return &Server{
		cfg:   cfg,
		guard: netutil.NewGuard(cfg.AllowPrivate),
		engine: scan.NewEngine(scan.Options{
			MaxConcurrency: cfg.MaxConcurrency,
			ModuleTimeout:  cfg.ModuleTimeout,
			ScanTimeout:    cfg.ScanTimeout,
		}),
		auth:     auth.New(cfg.APIKeys, cfg.APIRequireKey),
		limiter:  newRateLimiter(),
		cooldown: abuse.NewCooldown(cooldownWindow),
		metrics:  metrics.New(),
		started:  time.Now(),
	}
}

// Handler returns the fully-wrapped HTTP handler (routes + middleware).
//
// Middleware executes outside-in: logging → recover → request-id → security
// headers → CORS → auth → rate-limit → route. Auth runs before rate-limiting so
// limits are applied per-tier.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /v1/modules", s.handleModules)
	mux.HandleFunc("POST /v1/scan", s.handleScan)
	mux.HandleFunc("GET /v1/scan", s.handleScan) // convenience for ?target=

	h := http.Handler(mux)
	h = s.withRateLimit(h)
	h = s.withAuth(h)
	h = s.withCORS(h)
	h = s.withSecurityHeaders(h)
	h = s.withRecover(h)
	h = s.withLogging(h)   // captures final status; reads request-id from context
	h = s.withRequestID(h) // outermost: assigns the id before anything logs
	return h
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
