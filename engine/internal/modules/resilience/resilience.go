// Package resilience performs ownership-gated *availability* checks:
// rate-limit presence, graceful degradation under a tiny sequential probe
// budget, and Retry-After awareness.
//
// This is NOT volumetric DDoS. Flooding third-party or even owned production
// infrastructure is unsafe, often illegal without explicit change windows, and
// is intentionally out of scope. Use a dedicated load lab (k6/Locust against
// staging) for capacity testing. Here we send a small fixed number of
// sequential requests and observe 429/503/Retry-After behaviour.
package resilience

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "resilience" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Safe resilience checks: rate-limit headers & graceful 429 under tiny sequential load. Not DDoS. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

// probeCount is intentionally tiny — detection of controls, not capacity breaking.
const probeCount = 12

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host + "/"
	if !t.Scope.PathAllowed("/") {
		return []scan.Finding{info("Path / excluded by scope — resilience probe skipped.")}, nil
	}

	var (
		statuses     []int
		saw429       bool
		sawRetry     bool
		rateHeaders  []string
		errors       int
	)

	// Sequential only — never parallel flood.
	delay := 80 * time.Millisecond
	if t.Scope.RequestDelayMs > 0 {
		delay = time.Duration(t.Scope.RequestDelayMs) * time.Millisecond
	}

	for i := 0; i < probeCount; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				// stop early
				i = probeCount
				continue
			case <-time.After(delay):
			}
		}
		status, hdr, err := getOnce(ctx, env, base)
		if err != nil {
			errors++
			continue
		}
		statuses = append(statuses, status)
		if status == 429 {
			saw429 = true
		}
		if ra := hdr.Get("Retry-After"); ra != "" {
			sawRetry = true
		}
		for _, h := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "RateLimit-Limit", "RateLimit-Remaining"} {
			if v := hdr.Get(h); v != "" {
				rateHeaders = append(rateHeaders, h+"="+v)
			}
		}
	}

	return findings(statuses, saw429, sawRetry, unique(rateHeaders), errors), nil
}

func getOnce(ctx context.Context, env *scan.Env, rawURL string) (int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastionscan-Probe", "resilience-safe")
	req.Header.Set("X-Bastionscan-Owner-Verified", "1")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	return resp.StatusCode, resp.Header.Clone(), nil
}

func findings(statuses []int, saw429, sawRetry bool, rateHeaders []string, errors int) []scan.Finding {
	f := scan.Finding{
		ID: "active.resilience", Module: "resilience", Category: scan.CategoryActive,
		Title: "Availability & rate-limit controls", MaxPoints: 15,
		Reference: "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
	}
	if len(statuses) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusInfo, scan.SeverityInfo, 0
		f.MaxPoints = 0
		f.Detail = "Could not complete safe resilience probes (network errors)."
		return []scan.Finding{f}
	}

	// Score: presence of rate-limit signalling is a positive control.
	if len(rateHeaders) > 0 || saw429 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 15
		f.Detail = fmt.Sprintf(
			"Target advertises rate-limit controls under a tiny sequential probe (%d requests). "+
				"429=%v Retry-After=%v. This is not a capacity/DDoS test.",
			len(statuses), saw429, sawRetry,
		)
		f.Evidence = strings.Join(rateHeaders, ", ")
		if f.Evidence == "" {
			f.Evidence = "HTTP 429 observed under light sequential load"
		}
		return []scan.Finding{f}
	}

	// No rate-limit headers and no 429 — soft warn for public APIs.
	f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 8
	f.Detail = fmt.Sprintf(
		"No RateLimit headers or HTTP 429 across %d sequential GETs (errors=%d). "+
			"Consider edge rate limiting (CDN/WAF) for auth and API routes. "+
			"Bastionscan deliberately does not perform volumetric DDoS.",
		len(statuses), errors,
	)
	f.Evidence = "statuses: " + joinInts(statuses)
	f.Fix = "Enable WAF/CDN rate limits on login, OTP, and expensive API routes; return 429 with Retry-After; load-test only in staging with k6/Locust."
	return []scan.Finding{f}
}

func info(detail string) scan.Finding {
	return scan.Finding{
		ID: "active.resilience", Module: "resilience", Category: scan.CategoryActive,
		Title: "Availability & rate-limit controls", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
		Detail: detail,
	}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ",")
}
