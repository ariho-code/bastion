// Package cookies audits the Set-Cookie flags a site issues — Secure, HttpOnly,
// and SameSite — which together decide whether cookies can be stolen over
// plaintext, read by injected scripts, or sent in cross-site requests (CSRF).
package cookies

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module inspects cookies from the shared page fetch.
type Module struct{}

func (m *Module) ID() string              { return "cookies" }
func (m *Module) Category() scan.Category { return scan.CategoryCookies }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Cookie security audit: Secure, HttpOnly and SameSite flags"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)
	if page.Err != nil {
		return nil, page.Err
	}
	cookies := page.Cookies
	if len(cookies) == 0 {
		return []scan.Finding{{
			ID: "cookies.none", Category: scan.CategoryCookies,
			Title: "No cookies set", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "The site set no cookies on the landing response — nothing to audit.",
		}}, nil
	}

	var insecure, noHTTPOnly, weakSameSite []string
	for _, c := range cookies {
		if page.HTTPS && !c.Secure {
			insecure = append(insecure, c.Name)
		}
		if !c.HttpOnly {
			noHTTPOnly = append(noHTTPOnly, c.Name)
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == http.SameSiteDefaultMode {
			weakSameSite = append(weakSameSite, c.Name)
		}
	}

	total := len(cookies)
	return []scan.Finding{
		secureFinding(total, insecure, page.HTTPS),
		httpOnlyFinding(total, noHTTPOnly),
		sameSiteFinding(total, weakSameSite),
	}, nil
}

func secureFinding(total int, insecure []string, https bool) scan.Finding {
	f := scan.Finding{
		ID: "cookies.secure", Category: scan.CategoryCookies,
		Title: "Cookies marked Secure", MaxPoints: 12,
		Reference: "https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
	}
	if !https {
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "The Secure flag is only meaningful over HTTPS."
		return f
	}
	if len(insecure) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 12
		f.Detail = fmt.Sprintf("All %d cookie(s) are marked Secure.", total)
	} else {
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "Cookies without the Secure flag can be sent over plaintext HTTP and stolen."
		f.Evidence = list(insecure)
		f.Fix = "Add the Secure attribute to every cookie."
	}
	return f
}

func httpOnlyFinding(total int, noHTTPOnly []string) scan.Finding {
	f := scan.Finding{
		ID: "cookies.httponly", Category: scan.CategoryCookies,
		Title: "Cookies marked HttpOnly", MaxPoints: 10,
	}
	if len(noHTTPOnly) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = fmt.Sprintf("All %d cookie(s) are HttpOnly, keeping them out of reach of injected scripts.", total)
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 0
		f.Detail = "Cookies without HttpOnly can be read by JavaScript, so an XSS bug can steal sessions."
		f.Evidence = list(noHTTPOnly)
		f.Fix = "Add HttpOnly to cookies that don't need JS access (session/auth tokens especially)."
	}
	return f
}

func sameSiteFinding(total int, weak []string) scan.Finding {
	f := scan.Finding{
		ID: "cookies.samesite", Category: scan.CategoryCookies,
		Title: "Cookies use SameSite", MaxPoints: 8,
	}
	if len(weak) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 8
		f.Detail = fmt.Sprintf("All %d cookie(s) declare an explicit SameSite policy (Lax or Strict).", total)
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "Cookies without an explicit SameSite=Lax/Strict are more exposed to cross-site request forgery (CSRF)."
		f.Evidence = list(weak)
		f.Fix = "Set SameSite=Lax (or Strict) on cookies; only use SameSite=None with Secure when truly needed."
	}
	return f
}

func list(names []string) string {
	if len(names) > 8 {
		return strings.Join(names[:8], ", ") + fmt.Sprintf(" …+%d", len(names)-8)
	}
	return strings.Join(names, ", ")
}
