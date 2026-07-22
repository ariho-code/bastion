// Package authweak performs a *tiny*, rate-limited default-credential check
// against ownership-verified login forms only. This is not bulk brute-force:
// at most a handful of well-known defaults, with lockout detection and SafeMode
// hard caps. Full password spraying is intentionally out of scope.
package authweak

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/modules/activekit"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "authweak" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Default/weak credential probe on login forms (tiny list, lockout-aware). Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

// Tiny default set used by abandoned appliances and misconfigured panels.
// Intentionally small for precision and safety.
var defaults = []struct{ user, pass string }{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "123456"},
	{"root", "root"},
	{"test", "test"},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)
	client := activekit.NewClient(env, t)

	var loginForms []activekit.Form
	for _, f := range surface.Forms {
		if f.AuthLike {
			loginForms = append(loginForms, f)
		}
	}

	if len(loginForms) == 0 {
		return []scan.Finding{{
			ID: "active.authweak", Module: "authweak", Category: scan.CategoryActive,
			Title: "Default credential exposure", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "No login form with a password field was found on the entry page — default-credential probe skipped.",
		}}, nil
	}

	// SafeMode (default): only first 3 pairs; non-safe still capped at 5.
	pairs := defaults
	if t.Scope.IsSafe() && len(pairs) > 3 {
		pairs = pairs[:3]
	}

	form := loginForms[0]
	userField, passField := pickAuthFields(form.Fields)
	if userField == "" || passField == "" {
		return []scan.Finding{{
			ID: "active.authweak", Module: "authweak", Category: scan.CategoryActive,
			Title: "Default credential exposure", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "Login form detected but username/password field names could not be determined safely.",
		}}, nil
	}

	// Baseline failure body for comparison.
	baseFields := copyFields(form.Fields)
	baseFields[userField] = "bastion_nonexistent_user_9f3a"
	baseFields[passField] = "bastion_wrong_pass_9f3a"
	baseline := client.DoForm(ctx, form.Method, form.Action, baseFields)

	var accepted []string
	for i, pair := range pairs {
		if ctx.Err() != nil {
			break
		}
		if i > 0 {
			select {
			case <-ctx.Done():
				return findings(accepted, form.Action), ctx.Err()
			case <-time.After(1500 * time.Millisecond):
			}
		}
		fields := copyFields(form.Fields)
		fields[userField] = pair.user
		fields[passField] = pair.pass
		res := client.DoForm(ctx, form.Method, form.Action, fields)
		if res.Err != nil {
			continue
		}
		if looksLocked(res.Body) {
			return []scan.Finding{{
				ID: "active.authweak", Module: "authweak", Category: scan.CategoryActive,
				Title: "Default credential exposure", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
				MaxPoints: 20, Points: 20,
				Detail: "Login endpoint signaled lockout/rate-limit — credential probing stopped to avoid account disruption.",
				Evidence: "lockout indicator after probe",
			}}, nil
		}
		if looksAuthenticated(res, baseline) {
			accepted = append(accepted, pair.user+":"+pair.pass)
			break // one confirmed default is enough; do not continue
		}
	}

	return findings(accepted, form.Action), nil
}

func pickAuthFields(fields map[string]string) (user, pass string) {
	for n := range fields {
		low := strings.ToLower(n)
		if pass == "" && (low == "password" || low == "pass" || low == "passwd" || low == "pwd" || strings.Contains(low, "password")) {
			pass = n
		}
		if user == "" && (low == "username" || low == "user" || low == "email" || low == "login" || low == "userid" || strings.Contains(low, "user") || strings.Contains(low, "email")) {
			user = n
		}
	}
	return user, pass
}

func copyFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func looksLocked(body string) bool {
	low := strings.ToLower(body)
	for _, s := range []string{
		"too many attempts", "account locked", "try again later",
		"rate limit", "temporarily blocked", "captcha",
	} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return false
}

func looksAuthenticated(res, baseline activekit.ProbeResult) bool {
	if res.Err != nil {
		return false
	}
	// Redirect to dashboard / session cookie set + body no longer has password field.
	loc := ""
	if res.Header != nil {
		loc = res.Header.Get("Location")
		sc := res.Header.Get("Set-Cookie")
		if strings.Contains(strings.ToLower(sc), "session") || strings.Contains(strings.ToLower(sc), "auth") {
			if res.Status >= 300 && res.Status < 400 && loc != "" {
				return true
			}
		}
	}
	// Body differential vs known-bad login: success pages often drop the password field
	// and show "logout" / "dashboard" / "welcome".
	low := strings.ToLower(res.Body)
	baseLow := strings.ToLower(baseline.Body)
	successHints := 0
	for _, h := range []string{"logout", "sign out", "dashboard", "welcome back", "my account"} {
		if strings.Contains(low, h) && !strings.Contains(baseLow, h) {
			successHints++
		}
	}
	stillLogin := strings.Contains(low, `type="password"`) || strings.Contains(low, "type='password'")
	if successHints >= 1 && !stillLogin {
		return true
	}
	// Status flip 401/403 → 200 with different length can be noisy; require hints.
	return false
}

func findings(accepted []string, action string) []scan.Finding {
	f := scan.Finding{
		ID: "active.authweak", Module: "authweak", Category: scan.CategoryActive,
		Title: "Default credential exposure", MaxPoints: 30,
		Reference: "https://owasp.org/www-community/attacks/Credential_stuffing",
	}
	if len(accepted) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 30
		f.Detail = fmt.Sprintf("Login form at %s rejected the small default-credential set (safe, rate-limited probe).", action)
		return []scan.Finding{f}
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityCritical, 0
	f.Detail = "A well-known default username/password combination was accepted by the login form."
	f.Evidence = "accepted: " + strings.Join(accepted, ", ") + " on " + action
	f.Fix = "Force unique admin passwords at install, disable default accounts, enforce MFA, and lock out after repeated failures."
	return []scan.Finding{f}
}
