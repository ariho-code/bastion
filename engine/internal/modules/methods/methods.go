// Package methods probes which HTTP methods a server accepts — including TRACE
// (cross-site tracing / XST) and write methods like PUT/DELETE. Because it sends
// non-GET requests, it's an Active-tier module: it only runs against targets the
// caller has proven they own (see the verify package).
package methods

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module tests HTTP method exposure. Active tier (ownership-gated).
type Module struct{}

func (m *Module) ID() string              { return "methods" }
func (m *Module) Category() scan.Category { return scan.CategoryDisclosure }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "HTTP method exposure: TRACE (XST) and write methods (PUT/DELETE/PATCH). Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

var writeMethods = []string{"PUT", "DELETE", "PATCH", "CONNECT"}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host
	if page := env.Page(ctx, t); page.Err == nil && page.FinalURL != "" {
		if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
			base = u.Scheme + "://" + u.Host + "/"
		}
	}

	allow := optionsAllow(ctx, env, base)
	traceOn := traceEnabled(ctx, env, base)

	return []scan.Finding{traceFinding(traceOn), dangerousMethodsFinding(allow)}, nil
}

func optionsAllow(ctx context.Context, env *scan.Env, base string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, base, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", env.UserAgent)
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return strings.ToUpper(resp.Header.Get("Allow"))
}

func traceEnabled(ctx context.Context, env *scan.Env, base string) bool {
	req, err := http.NewRequestWithContext(ctx, "TRACE", base, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastion-Trace", "probe")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// TRACE is enabled if the server echoes the request back (200 + reflects it).
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "message/http")
}

func traceFinding(enabled bool) scan.Finding {
	f := scan.Finding{
		ID: "disclosure.http.trace", Category: scan.CategoryDisclosure,
		Title: "HTTP TRACE method", MaxPoints: 6,
		Reference: "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
	}
	if enabled {
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityMedium, 0
		f.Detail = "The TRACE method is enabled, enabling Cross-Site Tracing (XST) to read otherwise-protected headers."
		f.Fix = "Disable the TRACE method at the web server or WAF."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "The TRACE method is disabled."
	}
	return f
}

func dangerousMethodsFinding(allow string) scan.Finding {
	f := scan.Finding{
		ID: "disclosure.http.methods", Category: scan.CategoryDisclosure,
		Title: "HTTP write methods", MaxPoints: 6,
	}
	var found []string
	for _, m := range writeMethods {
		if strings.Contains(allow, m) {
			found = append(found, m)
		}
	}
	switch {
	case allow == "":
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "The server did not advertise its allowed methods (no Allow header on OPTIONS)."
	case len(found) == 0:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "No write methods (PUT/DELETE/PATCH/CONNECT) are advertised."
		f.Evidence = "Allow: " + allow
	default:
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 0
		f.Detail = "The server advertises write methods that should usually be disabled on public endpoints."
		f.Evidence = "Allow: " + allow
		f.Fix = "Restrict " + strings.Join(found, ", ") + " to authenticated APIs only; disable them elsewhere."
	}
	return f
}
