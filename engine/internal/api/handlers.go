package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// handleHealth reports liveness plus a snapshot of engine capabilities.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"version":   scan.EngineVersion,
		"modules":   len(scan.Modules()),
		"uptimeSec": int(time.Since(s.started).Seconds()),
		"time":      time.Now().UTC(),
	})
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
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target.Verified = req.Verified

	if err := s.guard.Check(r.Context(), target.Host); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	profile := scan.ParseProfile(req.Profile)
	result := s.engine.Run(r.Context(), target, profile)
	writeJSON(w, http.StatusOK, result)
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
