// Package csrf checks whether state-changing HTML forms on ownership-verified
// sites carry anti-CSRF tokens. Precision: only POST/PUT/PATCH/DELETE forms with
// password or sensitive field names escalate; GET search forms are ignored.
package csrf

import (
	"context"
	"fmt"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/modules/activekit"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "csrf" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "CSRF token presence on state-changing forms. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

var tokenNames = []string{
	"csrf", "csrftoken", "_csrf", "csrf_token", "csrfmiddlewaretoken",
	"__requestverificationtoken", "authenticity_token", "_token",
	"xsrf", "xsrf-token", "_xsrf", "antiforgery", "__csrf",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)

	var missing []string
	var protected int
	var stateChanging int

	for _, form := range surface.Forms {
		method := strings.ToUpper(form.Method)
		if method == "" || method == "GET" {
			continue
		}
		// Only care about forms that look security-sensitive.
		if !form.AuthLike && !sensitiveFields(form.Fields) {
			continue
		}
		stateChanging++
		if hasCSRFToken(form.Fields) {
			protected++
			continue
		}
		missing = append(missing, fmt.Sprintf("%s %s (fields: %s)",
			method, form.Action, fieldNames(form.Fields)))
	}

	return []scan.Finding{finding(missing, protected, stateChanging)}, nil
}

func sensitiveFields(fields map[string]string) bool {
	for n := range fields {
		low := strings.ToLower(n)
		for _, k := range []string{"password", "passwd", "email", "amount", "card", "cvv", "transfer", "pay", "delete", "account"} {
			if strings.Contains(low, k) {
				return true
			}
		}
	}
	return false
}

func hasCSRFToken(fields map[string]string) bool {
	for n := range fields {
		low := strings.ToLower(n)
		for _, t := range tokenNames {
			if low == t || strings.Contains(low, t) {
				return true
			}
		}
	}
	return false
}

func fieldNames(fields map[string]string) string {
	var names []string
	for n := range fields {
		names = append(names, n)
		if len(names) >= 6 {
			break
		}
	}
	return strings.Join(names, ", ")
}

func finding(missing []string, protected, total int) scan.Finding {
	f := scan.Finding{
		ID: "active.csrf", Module: "csrf", Category: scan.CategoryActive,
		Title: "Cross-site request forgery (CSRF) protections", MaxPoints: 25,
		Reference: "https://owasp.org/www-community/attacks/csrf",
	}
	if total == 0 {
		f.Status, f.Severity, f.Points = scan.StatusInfo, scan.SeverityInfo, 0
		f.MaxPoints = 0
		f.Detail = "No state-changing sensitive forms were found on the entry page to evaluate for CSRF tokens."
		return f
	}
	if len(missing) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 25
		f.Detail = fmt.Sprintf("All %d sensitive state-changing form(s) include an anti-CSRF token field.", total)
		return f
	}
	// Soft fail: missing token is high-risk for login/payment forms.
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = fmt.Sprintf("%d of %d sensitive form(s) lack a recognizable anti-CSRF token (%d protected).",
		len(missing), total, protected)
	f.Evidence = strings.Join(missing, " · ")
	f.Fix = "Embed a per-session CSRF token in every state-changing form and validate it server-side. Prefer SameSite=Lax/Strict cookies and check Origin/Referer as defense-in-depth."
	return f
}
