package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/abuse"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
	"github.com/ariho-code/bastionscan/engine/internal/verify"
)

// handleHealth reports liveness plus a snapshot of engine capabilities.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"version":      scan.EngineVersion,
		"modules":      len(scan.Modules()),
		"uptimeSec":    int(time.Since(s.started).Seconds()),
		"authRequired": s.auth.RequireKey(),
		"time":         time.Now().UTC(),
	})
}

// handleVerify issues the DNS TXT record an owner must publish to unlock
// Active-tier scans for their domain. Public and stateless — the token is a
// deterministic HMAC of the domain.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	target, err := scan.NewTarget(r.URL.Query().Get("target"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token := verify.Token(s.cfg.VerifySecret, target.Domain)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":      target.Domain,
		"recordName":  verify.RecordName,
		"recordType":  "TXT",
		"token":       token,
		"record":      verify.RecordName + "=" + token,
		"instruction": "Add a DNS TXT record on " + target.Domain + " with the value above, then scan with profile=active to unlock ownership-gated checks.",
	})
}

// handleMetrics exposes engine telemetry in Prometheus exposition format.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}

// handleModules lists every registered scanner module. This makes the engine's
// capabilities self-describing — the frontend can render them without a
// hardcoded list.
func (s *Server) handleModules(w http.ResponseWriter, r *http.Request) {
	mods := scan.Modules()
	out := make([]map[string]any, 0, len(mods))
	for _, m := range mods {
		out = append(out, map[string]any{
			"id":          m.ID(),
			"category":    m.Category(),
			"description": m.Description(),
			"minLevel":    m.MinLevel(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "modules": out})
}

type scanRequest struct {
	Target   string `json:"target"`
	Profile  string `json:"profile"`
	Verified bool   `json:"verified"`
}

// handleScan parses a scan request (JSON body or query params), enforces the
// SSRF guard, then runs the engine.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	req, err := parseScanRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := scan.NewTarget(req.Target)
	if err != nil {
		s.metrics.IncScanError()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target.Verified = req.Verified

	// Abuse validation beyond SSRF safety (embedded creds, non-web ports, …).
	if err := abuse.Validate(target); err != nil {
		s.metrics.IncScanError()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.guard.Check(r.Context(), target.Host); err != nil {
		s.metrics.IncScanError()
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	// Per-target cooldown: don't let the engine be used to flood one victim.
	if ok, retryAfter := s.cooldown.Check(target.Host); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests,
			"this target was scanned very recently; please wait before scanning it again")
		return
	}

	profile := scan.ParseProfile(req.Profile)
	env := &scan.Env{
		HTTP:      s.guard.HTTPClient(15 * time.Second),
		Resolver:  net.DefaultResolver,
		UserAgent: "BastionscanEngine/" + scan.EngineVersion + " (+https://bastionscan.com)",
	}

	// Ownership gating for the Active tier. The engine is authoritative: in
	// production it confirms the DNS token itself rather than trusting the
	// caller's flag. The caller flag is honored only in dev (ALLOW_PRIVATE).
	target.Verified = req.Verified && s.cfg.AllowPrivate
	if profile.Level >= scan.ProfileActive.Level && !target.Verified {
		target.Verified = verify.Verify(r.Context(), env, s.cfg.VerifySecret, target.Domain)
	}

	result := s.engine.Run(r.Context(), target, profile, env)
	s.metrics.IncScan()
	s.metrics.ObserveScan(float64(result.DurationMs) / 1000.0)
	s.auditScan(r, target, profile, result)
	writeJSON(w, http.StatusOK, result)
}

// auditScan emits a structured audit-trail line for every completed scan —
// distinct from the access log, and the record you'd keep for compliance.
func (s *Server) auditScan(r *http.Request, t *scan.Target, p scan.Profile, res *scan.ScanResult) {
	entry := map[string]any{
		"level":      "audit",
		"event":      "scan",
		"target":     t.Host,
		"profile":    p.Name,
		"grade":      res.Grade,
		"score":      res.Score,
		"dur_ms":     res.DurationMs,
		"ip":         s.clientIP(r),
		"tier":       string(identityFrom(r.Context()).Tier),
		"request_id": requestIDFrom(r.Context()),
		"ts":         time.Now().UTC().Format(time.RFC3339),
	}
	if b, err := json.Marshal(entry); err == nil {
		log.Println(string(b))
	}
}

func parseScanRequest(r *http.Request) (scanRequest, error) {
	var req scanRequest
	if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		defer r.Body.Close()
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(&req); err != nil {
			return req, &scan.ParseError{Msg: "invalid JSON body"}
		}
	}
	q := r.URL.Query()
	if req.Target == "" {
		req.Target = q.Get("target")
	}
	if req.Profile == "" {
		req.Profile = q.Get("profile")
	}
	if !req.Verified && q.Get("verified") == "true" {
		req.Verified = true
	}
	return req, nil
}
