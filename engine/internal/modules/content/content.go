// Package content grades the integrity of the delivered page — the risks that
// live in the HTML itself rather than in headers or transport. It reuses the
// engine's shared page fetch, so every markup check is free (no extra request):
// mixed content, missing Subresource Integrity, insecure form actions, and
// reverse-tabnabbing links. It adds one lightweight probe for a published
// security.txt (RFC 9116). This module fills the `content` category, giving the
// deep scan parity with — and depth beyond — the free client-side scanner.
package content

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module analyzes page content integrity from the shared HTML fetch.
type Module struct{}

func (m *Module) ID() string              { return "content" }
func (m *Module) Category() scan.Category { return scan.CategoryContent }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Page-content integrity: mixed content, Subresource Integrity, insecure forms, tabnabbing, security.txt"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)
	if page.Err != nil {
		return []scan.Finding{{
			ID: "content.unavailable", Category: scan.CategoryContent,
			Title: "Page content not analyzed", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "Could not fetch the page body to analyze its content.", Evidence: page.Err.Error(),
		}}, nil
	}

	pageHost := t.Host
	base := "https://" + t.Host
	if page.FinalURL != "" {
		if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
			pageHost = u.Hostname()
			base = u.Scheme + "://" + u.Host
		}
	}

	// The markup checks only make sense when we actually received HTML.
	findings := []scan.Finding{securityTxtFinding(ctx, env, base)}
	if strings.TrimSpace(page.Body) == "" {
		return findings, nil
	}
	body := page.Body
	findings = append(findings,
		mixedContentFinding(body, page.HTTPS),
		sriFinding(body, pageHost),
		formFinding(body, page.HTTPS),
		tabnabbingFinding(body),
	)
	return findings, nil
}

// --- markup extraction -------------------------------------------------------

// tagRe captures a resource-loading element and its full attribute blob;
// urlAttrRe then pulls the referenced URL out of that blob. Capturing the whole
// tag (not just the text up to the URL) is what lets us see attributes like
// integrity= or rel= that appear after src=. Case-insensitive, dotall so
// multi-line tags match.
var (
	tagRe     = regexp.MustCompile(`(?is)<(script|iframe|img|link|audio|video|source|object|embed|form)\b([^>]*)>`)
	urlAttrRe = regexp.MustCompile(`(?i)\b(?:src|href|action|data)\s*=\s*["']?\s*([^"'\s>]+)`)
)

// activeTags load code or submit data — insecure delivery is directly
// dangerous (script execution, data interception). Passive tags (images,
// media) are lower severity.
var activeTags = map[string]bool{
	"script": true, "iframe": true, "object": true, "embed": true, "form": true, "link": true,
}

type resourceRef struct {
	tag  string
	attr string // the raw attribute blob, for e.g. rel/integrity lookups
	url  string
}

func extractResources(body string) []resourceRef {
	matches := tagRe.FindAllStringSubmatch(body, -1)
	out := make([]resourceRef, 0, len(matches))
	for _, m := range matches {
		attrs := m[2]
		um := urlAttrRe.FindStringSubmatch(attrs)
		if um == nil {
			continue // element loads no sub-resource (e.g. inline <script>)
		}
		out = append(out, resourceRef{tag: strings.ToLower(m[1]), attr: attrs, url: um[1]})
	}
	return out
}

// --- mixed content -----------------------------------------------------------

func mixedContentFinding(body string, https bool) scan.Finding {
	f := scan.Finding{
		ID: "content.mixed", Category: scan.CategoryContent,
		Title: "Mixed content", MaxPoints: 12,
		Reference: "https://developer.mozilla.org/docs/Web/Security/Mixed_content",
	}
	if !https {
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "Mixed-content rules don't apply because the page was not served over HTTPS."
		return f
	}

	var active, passive []string
	for _, r := range extractResources(body) {
		if !strings.HasPrefix(strings.ToLower(r.url), "http://") {
			continue
		}
		sample := r.tag + " → " + clip(r.url, 70)
		if activeTags[r.tag] {
			active = append(active, sample)
		} else {
			passive = append(passive, sample)
		}
	}

	switch {
	case len(active) > 0:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "The HTTPS page loads active resources (scripts, frames, stylesheets or form targets) over plain http://. Browsers may block them, and a network attacker can tamper with them to run code in your page."
		f.Evidence = strings.Join(dedupeCap(active, 4), " · ")
		f.Fix = "Serve every sub-resource over https:// and add Content-Security-Policy: upgrade-insecure-requests."
	case len(passive) > 0:
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 6
		f.Detail = "The page loads passive resources (images or media) over http://. These are lower-risk but still leak and can be swapped by a network attacker."
		f.Evidence = strings.Join(dedupeCap(passive, 4), " · ")
		f.Fix = "Upgrade image/media URLs to https:// (or protocol-relative // at minimum)."
	default:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 12
		f.Detail = "Every sub-resource on the page is loaded over HTTPS — no insecure scripts, frames, or media."
	}
	return f
}

// --- subresource integrity ---------------------------------------------------

var integrityRe = regexp.MustCompile(`(?i)\bintegrity\s*=`)
var relStylesheetRe = regexp.MustCompile(`(?i)\brel\s*=\s*["']?[^"'>]*stylesheet`)

func sriFinding(body, pageHost string) scan.Finding {
	f := scan.Finding{
		ID: "content.sri", Category: scan.CategoryContent,
		Title: "Subresource Integrity", MaxPoints: 6,
		Reference: "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity",
	}
	var missing []string
	for _, r := range extractResources(body) {
		// Only third-party <script> and stylesheet <link> benefit from SRI.
		if r.tag != "script" && !(r.tag == "link" && relStylesheetRe.MatchString(r.attr)) {
			continue
		}
		if !isCrossOrigin(r.url, pageHost) {
			continue
		}
		if integrityRe.MatchString(r.attr) {
			continue
		}
		missing = append(missing, r.tag+" → "+clip(r.url, 70))
	}

	if len(missing) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "No third-party scripts or stylesheets are loaded without Subresource Integrity."
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 0
	f.Detail = "Third-party scripts/stylesheets are loaded without an integrity hash. If that CDN or host is compromised, malicious code runs with full access to your page."
	f.Evidence = strings.Join(dedupeCap(missing, 4), " · ")
	f.Fix = "Add integrity=\"sha384-…\" and crossorigin=\"anonymous\" to external <script>/<link> tags."
	return f
}

func isCrossOrigin(rawURL, pageHost string) bool {
	l := strings.ToLower(rawURL)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return false // relative or protocol-relative → same origin (or already handled by mixed-content)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return !strings.EqualFold(u.Hostname(), pageHost)
}

// --- insecure forms ----------------------------------------------------------

var formActionRe = regexp.MustCompile(`(?is)<form\b[^>]*?\baction\s*=\s*["']?\s*(http://[^"'\s>]+)`)

func formFinding(body string, https bool) scan.Finding {
	f := scan.Finding{
		ID: "content.form", Category: scan.CategoryContent,
		Title: "Form submission security", MaxPoints: 6,
	}
	if !https {
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "Form-target security is assessed only on HTTPS pages."
		return f
	}
	var insecure []string
	for _, m := range formActionRe.FindAllStringSubmatch(body, -1) {
		insecure = append(insecure, clip(m[1], 80))
	}
	if len(insecure) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "No forms submit to an insecure http:// endpoint."
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = "A form on this secure page submits to a plain-http:// URL, so anything the user types (credentials, personal data) is sent unencrypted."
	f.Evidence = strings.Join(dedupeCap(insecure, 3), " · ")
	f.Fix = "Point every form action at an https:// endpoint."
	return f
}

// --- reverse tabnabbing ------------------------------------------------------

var anchorRe = regexp.MustCompile(`(?is)<a\b([^>]*?)>`)
var targetBlankRe = regexp.MustCompile(`(?i)\btarget\s*=\s*["']?_blank`)
var relSafeRe = regexp.MustCompile(`(?i)\brel\s*=\s*["'][^"']*\bno(opener|referrer)\b`)
var hrefExternalRe = regexp.MustCompile(`(?i)\bhref\s*=\s*["']?https?://`)

func tabnabbingFinding(body string) scan.Finding {
	f := scan.Finding{
		ID: "content.tabnabbing", Category: scan.CategoryContent,
		Title: "Reverse tabnabbing", MaxPoints: 4,
		Reference: "https://owasp.org/www-community/attacks/Reverse_Tabnabbing",
	}
	count := 0
	for _, m := range anchorRe.FindAllStringSubmatch(body, -1) {
		attrs := m[1]
		if targetBlankRe.MatchString(attrs) && hrefExternalRe.MatchString(attrs) && !relSafeRe.MatchString(attrs) {
			count++
		}
	}
	if count == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 4
		f.Detail = "External links that open in a new tab set rel=\"noopener\" (or none do)."
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
	f.Detail = plural(count, "external link", "external links") + " open in a new tab without rel=\"noopener\", letting the opened page rewrite this tab's location (reverse tabnabbing). Most modern browsers now mitigate this by default, but the attribute makes the protection explicit."
	f.Fix = "Add rel=\"noopener noreferrer\" to every target=\"_blank\" link."
	return f
}

// --- security.txt (RFC 9116) -------------------------------------------------

func securityTxtFinding(ctx context.Context, env *scan.Env, base string) scan.Finding {
	f := scan.Finding{
		ID: "content.security-txt", Category: scan.CategoryContent,
		Title: "security.txt", MaxPoints: 4,
		Reference: "https://www.rfc-editor.org/rfc/rfc9116",
	}
	// RFC 9116 mandates /.well-known/; the legacy root path is a fallback.
	for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
		if body, ok := getText(ctx, env, base+path); ok && strings.Contains(strings.ToLower(body), "contact:") {
			f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 4
			f.Detail = "A security.txt is published, giving researchers a standard, machine-readable channel for responsible disclosure."
			f.Evidence = firstLine(body)
			return f
		}
	}
	f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
	f.Detail = "No /.well-known/security.txt was found. Publishing one gives security researchers a clear contact for reporting vulnerabilities (RFC 9116)."
	f.Fix = "Serve /.well-known/security.txt with at least a Contact: and Expires: field."
	return f
}

func getText(ctx context.Context, env *scan.Env, u string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	// A security.txt must be text/plain; an HTML soft-404 doesn't count.
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); ct != "" && !strings.Contains(ct, "text/plain") {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	return string(body), true
}

// --- helpers -----------------------------------------------------------------

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return clip(strings.TrimSpace(s[:i]), 120)
	}
	return clip(strings.TrimSpace(s), 120)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// dedupeCap removes duplicate samples (a page often repeats the same bad URL)
// and caps the list so evidence strings stay readable.
func dedupeCap(items []string, max int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if seen[it] {
			continue
		}
		seen[it] = true
		out = append(out, it)
	}
	sort.Strings(out)
	if len(out) > max {
		out = append(out[:max], "…+"+itoa(len(out)-max)+" more")
	}
	return out
}
