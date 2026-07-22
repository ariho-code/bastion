// Package inject detects path traversal / LFI and basic command-injection
// *indicators* on ownership-verified targets. Reporting requires strong
// content fingerprints (e.g. /etc/passwd shape) — not mere 200 OK responses.
package inject

import (
	"context"
	"fmt"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/modules/activekit"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "inject" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Path traversal / LFI detection with strong content fingerprints. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

var traversalPayloads = []string{
	"../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2fetc%2fpasswd",
	"..\\..\\..\\..\\windows\\win.ini",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)
	client := activekit.NewClient(env, t)

	var hits []string
	tested := 0

	fileParams := filterFileish(surface.Params)
	for _, p := range fileParams {
		if ctx.Err() != nil || tested >= 16 {
			break
		}
		for _, payload := range traversalPayloads {
			if ctx.Err() != nil {
				break
			}
			tested++
			res := client.DoGET(ctx, p.Action, map[string]string{p.Name: payload})
			if p.In == "body" {
				res = client.DoForm(ctx, p.Method, p.Action, map[string]string{p.Name: payload})
			}
			if res.Err != nil {
				continue
			}
			if looksLikePasswd(res.Body) {
				hits = append(hits, fmt.Sprintf("param %q on %s returned /etc/passwd-like content", p.Name, p.Action))
				break
			}
			if looksLikeWinINI(res.Body) {
				hits = append(hits, fmt.Sprintf("param %q on %s returned win.ini-like content", p.Name, p.Action))
				break
			}
		}
	}

	// Generic file= probe on homepage when no file-ish params.
	if tested == 0 {
		for _, payload := range traversalPayloads[:2] {
			tested++
			res := client.DoGET(ctx, surface.Base+"/", map[string]string{"file": payload, "path": payload, "page": payload})
			if res.Err == nil && (looksLikePasswd(res.Body) || looksLikeWinINI(res.Body)) {
				hits = append(hits, "homepage file/path/page traversal probe returned OS file content")
				break
			}
		}
	}

	return []scan.Finding{finding(hits, tested)}, nil
}

func filterFileish(params []activekit.Param) []activekit.Param {
	var out []activekit.Param
	for _, p := range params {
		n := strings.ToLower(p.Name)
		for _, k := range []string{"file", "path", "dir", "folder", "doc", "document", "page", "template", "include", "load", "view", "doc_path"} {
			if n == k || strings.Contains(n, k) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

func looksLikePasswd(body string) bool {
	// Classic passwd lines: root:x:0:0: or root:*:0:0:
	if strings.Contains(body, "root:x:0:0:") || strings.Contains(body, "root:*:0:0:") {
		return true
	}
	// Require multiple user-like lines to avoid FP on docs that mention the format.
	if strings.Count(body, ":/bin/") >= 3 && strings.Contains(body, "root:") {
		return true
	}
	return false
}

func looksLikeWinINI(body string) bool {
	return strings.Contains(body, "[fonts]") && strings.Contains(body, "[extensions]")
}

func finding(hits []string, tested int) scan.Finding {
	f := scan.Finding{
		ID: "active.lfi", Module: "inject", Category: scan.CategoryActive,
		Title: "Path traversal / local file inclusion", MaxPoints: 35,
		Reference: "https://owasp.org/www-community/attacks/Path_Traversal",
	}
	if len(hits) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 35
		f.Detail = fmt.Sprintf("No OS file fingerprints across %d traversal probe(s).", tested)
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityCritical, 0
	f.Detail = "Traversal payloads returned operating-system file content — the app is reading arbitrary paths."
	f.Evidence = strings.Join(hits, " · ")
	f.Fix = "Never pass user input into filesystem APIs. Use allow-lists of resource IDs, chroot/jail document roots, and reject path separators and .. segments."
	return f
}
