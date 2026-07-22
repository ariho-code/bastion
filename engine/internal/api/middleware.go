package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/auth"
)

// withRecover turns a panic in any handler into a clean 500 instead of dropping
// the connection.
func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf(`{"level":"error","msg":"panic","request_id":%q,"err":"%v"}`,
					requestIDFrom(r.Context()), rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withRequestID assigns a unique ID to every request, echoes it in the
// X-Request-ID header, and stashes it in context for correlated logging.
func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(withRequestIDValue(r.Context(), id)))
	})
}

// withSecurityHeaders applies defense-in-depth response headers. The engine
// dogfoods the very controls it audits for.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), interest-cohort=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// Render terminates TLS, so clients always reach us over HTTPS.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// withLogging emits a structured JSON access log per request.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		entry := map[string]any{
			"level":      "info",
			"ts":         start.UTC().Format(time.RFC3339),
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     sw.status,
			"dur_ms":     time.Since(start).Milliseconds(),
			"ip":         s.clientIP(r),
			"request_id": requestIDFrom(r.Context()),
			"tier":       string(identityFrom(r.Context()).Tier),
		}
		if b, err := json.Marshal(entry); err == nil {
			log.Println(string(b))
		}
	})
}

// withCORS applies the configured cross-origin policy so the frontend can call
// the engine directly from the browser.
func (s *Server) withCORS(next http.Handler) http.Handler {
	allowAny := false
	allowed := map[string]bool{}
	for _, o := range s.cfg.AllowedOrigins {
		if o == "*" {
			allowAny = true
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (allowAny || allowed[origin]) {
			if allowAny {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isProtected reports whether a path requires authentication when API_REQUIRE_KEY
// is set. Health, capability discovery, and metrics stay public.
func isProtected(path string) bool {
	return strings.HasPrefix(path, "/v1/scan")
}

// withAuth resolves the API identity, attaches it to context, and enforces the
// key requirement on protected routes.
func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, valid := s.auth.Authenticate(r)
		if s.auth.RequireKey() && !valid && isProtected(r.URL.Path) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="bastionscan"`)
			writeError(w, http.StatusUnauthorized, "a valid API key is required; pass it as 'Authorization: Bearer <key>' or 'X-API-Key'")
			return
		}
		next.ServeHTTP(w, r.WithContext(withIdentity(r.Context(), identity)))
	})
}

// withRateLimit applies a per-identity token bucket whose capacity depends on
// the caller's tier, and sets standard X-RateLimit-* headers.
func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		id := identityFrom(r.Context())
		limit := s.tierLimit(id.Tier)
		if limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		bucketKey := "ip:" + s.clientIP(r)
		if id.Tier != auth.TierAnonymous && id.KeyID != "" {
			bucketKey = "key:" + id.KeyID
		}
		res := s.limiter.take(bucketKey, limit)

		h := w.Header()
		h.Set("X-RateLimit-Limit", strconv.Itoa(limit))
		h.Set("X-RateLimit-Remaining", strconv.Itoa(res.remaining))
		h.Set("X-RateLimit-Reset", strconv.Itoa(res.resetSec))
		if !res.allowed {
			h.Set("Retry-After", strconv.Itoa(res.resetSec))
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) tierLimit(t auth.Tier) int {
	switch t {
	case auth.TierAgency:
		return s.cfg.RateLimitRPMAgency
	case auth.TierPro:
		return s.cfg.RateLimitRPMPro
	case auth.TierFree:
		return s.cfg.RateLimitRPMFree
	default:
		return s.cfg.RateLimitRPM
	}
}

// clientIP resolves the caller's address. X-Forwarded-For is only trusted when
// the engine sits behind a known proxy (TRUSTED_PROXY=true), preventing header
// spoofing of the rate-limit key.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// --- per-identity token bucket ----------------------------------------------

type bucket struct {
	tokens   float64
	capacity float64
	last     time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*bucket{}}
}

type limitResult struct {
	allowed   bool
	remaining int
	resetSec  int
}

// take consumes one token for key under the given per-minute limit, creating or
// re-scaling the bucket as needed.
func (l *rateLimiter) take(key string, rpm int) limitResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	capacity := float64(rpm)
	rate := capacity / 60.0

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: capacity, capacity: capacity, last: now}
		l.buckets[key] = b
	}
	// Re-scale if the tier's limit changed between calls.
	if b.capacity != capacity {
		b.capacity = capacity
		if b.tokens > capacity {
			b.tokens = capacity
		}
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > capacity {
		b.tokens = capacity
	}
	b.last = now

	if b.tokens < 1 {
		// Seconds until one token is available.
		reset := int((1 - b.tokens) / rate)
		if reset < 1 {
			reset = 1
		}
		return limitResult{allowed: false, remaining: 0, resetSec: reset}
	}
	b.tokens--
	// Seconds until the bucket is full again.
	reset := int((capacity - b.tokens) / rate)
	if reset < 1 {
		reset = 1
	}
	return limitResult{allowed: true, remaining: int(b.tokens), resetSec: reset}
}
