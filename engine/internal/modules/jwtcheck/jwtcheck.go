// Package jwtcheck looks for JWTs in cookies/headers/body on ownership-verified
// targets and flags dangerous algorithm configurations (alg=none, empty kid
// tricks) without attempting offline secret cracking.
package jwtcheck

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "jwtcheck" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "JWT hygiene: detect alg=none and unsigned tokens in cookies/page. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)
	var tokens []string
	if page != nil && page.Err == nil {
		for _, c := range page.Cookies {
			if looksJWT(c.Value) {
				tokens = append(tokens, c.Value)
			}
		}
		tokens = append(tokens, findJWTs(page.Body)...)
		for _, h := range []string{"Authorization", "X-Auth-Token", "X-Access-Token"} {
			if v := page.Header.Get(h); looksJWT(strings.TrimPrefix(v, "Bearer ")) {
				tokens = append(tokens, strings.TrimPrefix(v, "Bearer "))
			}
		}
	}

	var issues []string
	seen := map[string]bool{}
	for _, tok := range tokens {
		if seen[tok] {
			continue
		}
		seen[tok] = true
		if issue := inspectJWT(tok); issue != "" {
			issues = append(issues, issue)
		}
	}

	return []scan.Finding{finding(issues, len(seen))}, nil
}

func looksJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && len(parts[0]) > 10 && len(parts[1]) > 4
}

func findJWTs(body string) []string {
	// Rough scan for eyJ...eyJ...sig patterns.
	var out []string
	for _, part := range strings.FieldsFunc(body, func(r rune) bool {
		return r == '"' || r == '\'' || r == ' ' || r == '<' || r == '>' || r == '\n' || r == ','
	}) {
		if looksJWT(part) && strings.HasPrefix(part, "eyJ") {
			out = append(out, part)
			if len(out) >= 10 {
				break
			}
		}
	}
	return out
}

func inspectJWT(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// try std padding
		hdrJSON, err = base64.URLEncoding.DecodeString(pad(parts[0]))
		if err != nil {
			return ""
		}
	}
	var hdr map[string]any
	if json.Unmarshal(hdrJSON, &hdr) != nil {
		return ""
	}
	alg, _ := hdr["alg"].(string)
	alg = strings.ToLower(alg)
	if alg == "none" || alg == "" {
		return "JWT uses alg=none (or empty) — signature verification may be bypassable"
	}
	if parts[2] == "" || parts[2] == "\n" {
		return "JWT has an empty signature segment"
	}
	return ""
}

func pad(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

func finding(issues []string, found int) scan.Finding {
	f := scan.Finding{
		ID: "active.jwt", Module: "jwtcheck", Category: scan.CategoryActive,
		Title: "JWT configuration", MaxPoints: 20,
		Reference: "https://owasp.org/www-community/vulnerabilities/JSON_Web_Token_(JWT)_Misconfiguration",
	}
	if found == 0 {
		f.Status, f.Severity, f.Points = scan.StatusInfo, scan.SeverityInfo, 0
		f.MaxPoints = 0
		f.Detail = "No JWT-shaped tokens were observed in cookies or page content."
		return f
	}
	if len(issues) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 20
		f.Detail = "Observed JWT(s) do not use alg=none or empty signatures. (Offline secret cracking is not performed.)"
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = "JWT misconfiguration detected that can enable authentication bypass."
	f.Evidence = strings.Join(issues, " · ")
	f.Fix = "Reject alg=none. Explicitly allow-list algorithms (e.g. RS256). Validate signature, exp, aud, and iss on every request."
	return f
}
