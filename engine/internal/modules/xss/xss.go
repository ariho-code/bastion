// Package xss detects reflected cross-site scripting on ownership-verified
// targets. It only reports when a unique canary is reflected *unencoded* in the
// response — HTML-escaped reflections are treated as safe (no false positive).
package xss

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/modules/activekit"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "xss" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Reflected XSS detection via unique unencoded canaries. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)
	client := activekit.NewClient(env, t)

	var hits []string
	tested := 0

	for _, p := range surface.Params {
		if ctx.Err() != nil || tested >= 20 {
			break
		}
		// Unique marker — never a real exploit payload.
		marker := activekit.Canary("bxss")
		payload := `"><bs-` + marker + `>`
		tested++
		var res activekit.ProbeResult
		if p.In == "body" || strings.EqualFold(p.Method, http.MethodPost) {
			fields := map[string]string{p.Name: payload}
			res = client.DoForm(ctx, p.Method, p.Action, fields)
		} else {
			res = client.DoGET(ctx, p.Action, map[string]string{p.Name: payload})
		}
		if res.Err != nil {
			continue
		}
		// High precision: full unencoded canary fragment in HTML/JS context.
		if activekit.ContainsUnencoded(res.Body, "bs-"+marker) || activekit.ContainsUnencoded(res.Body, payload) {
			hits = append(hits, fmt.Sprintf("%s param %q reflects unencoded canary", p.Action, p.Name))
		}
	}

	// Homepage q= probe when no params discovered.
	if tested == 0 {
		marker := activekit.Canary("bxss")
		payload := `"><bs-` + marker + `>`
		res := client.DoGET(ctx, surface.Base+"/", map[string]string{"q": payload, "search": payload})
		tested++
		if res.Err == nil && activekit.ContainsUnencoded(res.Body, "bs-"+marker) {
			hits = append(hits, "homepage search reflects unencoded canary")
		}
	}

	return []scan.Finding{finding(hits, tested)}, nil
}

func finding(hits []string, tested int) scan.Finding {
	f := scan.Finding{
		ID: "active.xss", Module: "xss", Category: scan.CategoryActive,
		Title: "Reflected cross-site scripting (XSS)", MaxPoints: 35,
		Reference: "https://owasp.org/www-community/attacks/xss/",
	}
	if len(hits) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 35
		f.Detail = fmt.Sprintf("No unencoded reflection of XSS canaries across %d probe(s). Encoded reflections are not reported.", tested)
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = "User-controlled input is reflected without encoding — browsers may execute injected script in a victim session."
	f.Evidence = strings.Join(hits, " · ")
	f.Fix = "Context-aware output encoding (HTML/attr/JS/URL). Prefer templating auto-escape. Deploy a strict Content-Security-Policy as defense-in-depth."
	return f
}
