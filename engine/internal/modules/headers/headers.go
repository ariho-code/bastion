// Package headers grades a site's HTTP response security headers — the
// browser-enforced controls (CSP, framing, MIME sniffing, HSTS, referrer and
// permissions policy) that blunt XSS, clickjacking, and downgrade attacks.
package headers

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module analyzes response security headers from the shared page fetch.
type Module struct{}

func (m *Module) ID() string              { return "headers" }
func (m *Module) Category() scan.Category { return scan.CategoryHeaders }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Security header analysis: CSP, clickjacking, MIME sniffing, HSTS, referrer & permissions policy"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)
	if page.Err != nil {
		return nil, page.Err
	}
	h := page.Header
	return []scan.Finding{
		cspFinding(h),
		clickjackingFinding(h),
		nosniffFinding(h),
		referrerFinding(h),
		permissionsFinding(h),
		hstsFinding(h, page.HTTPS),
		crossOriginFinding(h),
	}, nil
}

func cspFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.csp", Category: scan.CategoryHeaders,
		Title: "Content-Security-Policy", MaxPoints: 15,
		Reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
	}
	csp := h.Get("Content-Security-Policy")
	switch {
	case csp == "":
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "No Content-Security-Policy. CSP is the strongest defense against cross-site scripting (XSS)."
		f.Fix = "Add a Content-Security-Policy header; start with default-src 'self' and tighten from there."
	case hasUnsafe(csp):
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 9
		f.Detail = "A CSP is present but allows 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection."
		f.Evidence = clip(csp, 160)
		f.Fix = "Remove 'unsafe-inline'/'unsafe-eval'; use nonces or hashes for inline scripts."
	default:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 15
		f.Detail = "A Content-Security-Policy is set without obvious unsafe directives."
		f.Evidence = clip(csp, 160)
	}
	return f
}

var unsafeRe = regexp.MustCompile(`(?i)'unsafe-(inline|eval)'`)

func hasUnsafe(csp string) bool { return unsafeRe.MatchString(csp) }

func clickjackingFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.clickjacking", Category: scan.CategoryHeaders,
		Title: "Clickjacking protection", MaxPoints: 10,
		Reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
	}
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	csp := strings.ToLower(h.Get("Content-Security-Policy"))
	frameAncestors := strings.Contains(csp, "frame-ancestors")
	switch {
	case frameAncestors || xfo == "DENY" || xfo == "SAMEORIGIN":
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "Framing is restricted (X-Frame-Options or CSP frame-ancestors), preventing clickjacking."
	default:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityMedium, 0
		f.Detail = "No framing protection. The page can be embedded in an attacker's iframe (clickjacking)."
		f.Fix = "Set X-Frame-Options: DENY or a CSP frame-ancestors 'none' directive."
	}
	return f
}

func nosniffFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.nosniff", Category: scan.CategoryHeaders,
		Title: "X-Content-Type-Options", MaxPoints: 8,
	}
	if strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 8
		f.Detail = "MIME-type sniffing is disabled (nosniff)."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "Missing X-Content-Type-Options: nosniff — browsers may MIME-sniff responses."
		f.Fix = "Add X-Content-Type-Options: nosniff."
	}
	return f
}

func referrerFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.referrer", Category: scan.CategoryHeaders,
		Title: "Referrer-Policy", MaxPoints: 6,
	}
	if h.Get("Referrer-Policy") != "" {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "A Referrer-Policy is set, controlling how much referrer data leaks to other origins."
		f.Evidence = h.Get("Referrer-Policy")
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "No Referrer-Policy — full URLs may leak to third parties via the Referer header."
		f.Fix = "Add Referrer-Policy: strict-origin-when-cross-origin (or stricter)."
	}
	return f
}

func permissionsFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.permissions", Category: scan.CategoryHeaders,
		Title: "Permissions-Policy", MaxPoints: 6,
	}
	if h.Get("Permissions-Policy") != "" || h.Get("Feature-Policy") != "" {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "A Permissions-Policy restricts access to powerful browser features (camera, geolocation, etc.)."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "No Permissions-Policy — powerful features aren't explicitly restricted."
		f.Fix = "Add a Permissions-Policy disabling features you don't use (e.g. geolocation=(), camera=())."
	}
	return f
}

var maxAgeRe = regexp.MustCompile(`(?i)max-age=(\d+)`)

// hstsFinding grades Strict-Transport-Security. HSTS enforces TLS, so it lives
// in the transport category alongside the certificate checks.
func hstsFinding(h http.Header, https bool) scan.Finding {
	f := scan.Finding{
		ID: "transport.hsts", Category: scan.CategoryTransport,
		Title: "HTTP Strict Transport Security", MaxPoints: 12,
		Reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
	}
	hsts := h.Get("Strict-Transport-Security")
	if !https {
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "HSTS is not applicable because the site was not served over HTTPS."
		return f
	}
	var maxAge int
	if mm := maxAgeRe.FindStringSubmatch(hsts); mm != nil {
		maxAge, _ = strconv.Atoi(mm[1])
	}
	switch {
	case hsts == "":
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityMedium, 0
		f.Detail = "No HSTS header. Browsers may be downgraded to HTTP on the first visit."
		f.Fix = "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
	case maxAge < 15768000: // ~6 months
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 7
		f.Detail = "HSTS is enabled but max-age is short. Aim for at least 6 months (ideally 1 year)."
		f.Evidence = hsts
		f.Fix = "Increase max-age to 31536000 and add includeSubDomains."
	default:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 12
		f.Detail = "HSTS is enabled with a strong max-age."
		f.Evidence = hsts
	}
	return f
}

func crossOriginFinding(h http.Header) scan.Finding {
	f := scan.Finding{
		ID: "headers.cross-origin", Category: scan.CategoryHeaders,
		Title: "Cross-origin isolation", MaxPoints: 4,
	}
	set := 0
	for _, k := range []string{"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy"} {
		if h.Get(k) != "" {
			set++
		}
	}
	switch {
	case set >= 2:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 4
		f.Detail = "Cross-origin isolation headers (COOP/COEP/CORP) are configured."
	case set == 1:
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 2
		f.Detail = "Only one cross-origin isolation header is set; consider the full COOP + COEP + CORP set."
	default:
		f.Status, f.Severity, f.Points = scan.StatusInfo, scan.SeverityInfo, 0
		f.MaxPoints = 0 // informational when entirely absent — not every site needs isolation
		f.Detail = "No cross-origin isolation headers. Recommended for sites using SharedArrayBuffer or sensitive cross-origin data."
	}
	return f
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
