// Package loadbound runs a *hard-capped* concurrent load against ownership-verified
// targets when the owner opts in (intensity=aggressive + consentLoad=true).
//
// This is NOT a volumetric DDoS kit:
//   - single scanner origin (no botnet / IP hopping network)
//   - hard max concurrency, request count, and wall-clock duration
//   - only paths allowed by enterprise scope
//   - labeled X-Bastionscan headers for WAF allow-listing during authorized windows
//
// Use this to verify rate limits and graceful degradation under realistic
// authorized pressure. For multi-region capacity tests, run k6 from the owner's
// own cloud accounts — Bastionscan will not open-proxy floods.
package loadbound

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "loadbound" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Bounded concurrent load (opt-in aggressive). Verifies rate limits — not DDoS. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool {
	return t.Host != "" && t.Verified &&
		t.Scope.NormalizedIntensity() == "aggressive" &&
		t.Scope.ConsentLoad
}

// Absolute ceilings — never exceed even if misconfigured.
const (
	maxWorkers   = 12
	maxRequests  = 400
	maxDuration  = 35 * time.Second
	perReqTimeout = 4 * time.Second
)

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	paths := []string{"/"}
	if len(t.Scope.IncludePaths) > 0 {
		paths = nil
		for _, p := range t.Scope.IncludePaths {
			if t.Scope.PathAllowed(p) {
				paths = append(paths, p)
			}
		}
		if len(paths) == 0 {
			paths = []string{"/"}
		}
	}
	// Never hit excluded paths; filter defaults.
	var targets []string
	for _, p := range paths {
		if !t.Scope.PathAllowed(p) {
			continue
		}
		targets = append(targets, "https://"+t.Host+ensureSlash(p))
	}
	if len(targets) == 0 {
		return []scan.Finding{{
			ID: "active.loadbound", Module: "loadbound", Category: scan.CategoryActive,
			Title: "Bounded load resilience", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "No in-scope paths available for bounded load (check exclude/include).",
		}}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	var (
		okN, failN, s429, s5xx int64
		wg                     sync.WaitGroup
		sem                    = make(chan struct{}, maxWorkers)
		sent                   int64
	)

	start := time.Now()
	for atomic.LoadInt64(&sent) < maxRequests {
		if ctx.Err() != nil {
			break
		}
		n := atomic.AddInt64(&sent, 1)
		if n > maxRequests {
			break
		}
		url := targets[int(n-1)%len(targets)]
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			status, err := one(ctx, env, u)
			if err != nil {
				atomic.AddInt64(&failN, 1)
				return
			}
			atomic.AddInt64(&okN, 1)
			if status == 429 {
				atomic.AddInt64(&s429, 1)
			}
			if status >= 500 {
				atomic.AddInt64(&s5xx, 1)
			}
		}(url)
	}
	wg.Wait()
	elapsed := time.Since(start)

	return []scan.Finding{result(okN, failN, s429, s5xx, sent, elapsed)}, nil
}

func one(ctx context.Context, env *scan.Env, rawURL string) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, perReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastionscan-Probe", "loadbound")
	req.Header.Set("X-Bastionscan-Owner-Verified", "1")
	req.Header.Set("X-Bastionscan-Intensity", "aggressive")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}

func result(ok, fail, r429, s5xx, sent int64, elapsed time.Duration) scan.Finding {
	f := scan.Finding{
		ID: "active.loadbound", Module: "loadbound", Category: scan.CategoryActive,
		Title: "Bounded load resilience (opt-in)", MaxPoints: 20,
		Reference: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
	}
	rps := float64(ok+fail) / elapsed.Seconds()
	f.Evidence = fmt.Sprintf("sent≈%d ok=%d err=%d http429=%d http5xx=%d duration=%s rps≈%.1f workers≤%d",
		sent, ok, fail, r429, s5xx, elapsed.Round(time.Millisecond), rps, maxWorkers)

	// Healthy: either rate limits engage or service stays mostly 2xx/3xx/4xx without collapse.
	if s5xx > ok/3 && s5xx > 10 {
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "Under bounded concurrent load the origin returned a high rate of 5xx — likely insufficient capacity or missing queue degradation."
		f.Fix = "Add autoscaling, queue expensive work, return 503 with Retry-After, and enforce edge rate limits before origin."
		return f
	}
	if r429 > 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 20
		f.Detail = "Rate limiting engaged (HTTP 429) under authorized bounded load — good control. This is not a volumetric DDoS simulation."
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 10
	f.Detail = "Bounded load completed without 429 responses. Consider edge rate limits on public endpoints. Multi-IP botnet simulation is intentionally unsupported."
	f.Fix = "Configure CDN/WAF rate limits and bot management; run multi-region capacity tests from your own cloud (k6) in a change window."
	return f
}

func ensureSlash(p string) string {
	if p == "" || p[0] != '/' {
		return "/" + p
	}
	return p
}
