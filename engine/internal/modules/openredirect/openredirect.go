// Package openredirect detects open redirects on ownership-verified targets by
// submitting an external canary URL into redirect-style parameters and checking
// whether the response Location (or meta refresh) points off-site.
package openredirect

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/modules/activekit"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "openredirect" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Open redirect detection on redirect/next/return URL parameters. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

var redirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_url",
	"next", "continue", "url", "goto", "dest", "destination", "redir", "rurl",
	"target", "forward", "link", "out",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)
	client := activekit.NewClient(env, t)
	canaryHost := "bastion-redirect-canary.example"
	canary := "https://" + canaryHost + "/probe"

	var hits []string
	tested := 0

	// Params already named like redirects.
	for _, p := range surface.Params {
		if !isRedirectName(p.Name) {
			continue
		}
		if ctx.Err() != nil || tested >= 12 {
			break
		}
		tested++
		res := client.DoGET(ctx, p.Action, map[string]string{p.Name: canary})
		if res.Err != nil {
			continue
		}
		if redirectsTo(res, canaryHost) {
			hits = append(hits, fmt.Sprintf("param %q on %s redirects to external canary", p.Name, p.Action))
		}
	}

	// Always try common names on homepage once each (scoped).
	if tested < 6 {
		for _, name := range redirectParams[:6] {
			if ctx.Err() != nil {
				break
			}
			tested++
			res := client.DoGET(ctx, surface.Base+"/", map[string]string{name: canary})
			if res.Err == nil && redirectsTo(res, canaryHost) {
				hits = append(hits, fmt.Sprintf("homepage param %q issues external redirect", name))
			}
		}
	}

	return []scan.Finding{finding(hits, tested)}, nil
}

func isRedirectName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range redirectParams {
		if n == p || strings.Contains(n, p) {
			return true
		}
	}
	return false
}

func redirectsTo(res activekit.ProbeResult, host string) bool {
	if res.Header != nil {
		loc := res.Header.Get("Location")
		if loc != "" {
			if u, err := url.Parse(loc); err == nil {
				if strings.EqualFold(u.Hostname(), host) {
					return true
				}
			}
			if strings.Contains(strings.ToLower(loc), host) {
				return true
			}
		}
	}
	low := strings.ToLower(res.Body)
	// meta refresh or JS location assignments to canary
	if strings.Contains(low, host) && (strings.Contains(low, "http-equiv=\"refresh\"") ||
		strings.Contains(low, "location.href") || strings.Contains(low, "location.replace")) {
		return true
	}
	return false
}

func finding(hits []string, tested int) scan.Finding {
	f := scan.Finding{
		ID: "active.openredirect", Module: "openredirect", Category: scan.CategoryActive,
		Title: "Open redirect", MaxPoints: 20,
		Reference: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
	}
	if len(hits) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 20
		f.Detail = fmt.Sprintf("No external redirects to the canary host across %d probe(s).", tested)
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityMedium, 0
	f.Detail = "The application redirects users to an attacker-controlled external URL based on request parameters."
	f.Evidence = strings.Join(hits, " · ")
	f.Fix = "Allow-list redirect targets (relative paths only, or exact known domains). Never trust raw user-supplied absolute URLs for Location headers."
	return f
}
