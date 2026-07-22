// Package wafdetect fingerprints WAF/CDN presence — classic attacker recon
// that enterprises need to verify their edge is actually engaged.
// Ownership-gated Active module.
package wafdetect

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "wafdetect" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "WAF/CDN fingerprinting (attacker recon simulation). Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

var fingerprints = []struct {
	name string
	hdr  string
	body string
}{
	{"Cloudflare", "cf-ray", "cloudflare"},
	{"Cloudflare", "cf-cache-status", ""},
	{"Akamai", "akamai", ""},
	{"AWS WAF/CloudFront", "x-amz-cf-id", ""},
	{"AWS WAF/CloudFront", "x-amzn-requestid", ""},
	{"Fastly", "x-served-by", "fastly"},
	{"Sucuri", "x-sucuri-id", "sucuri"},
	{"Imperva", "x-iinfo", "incapsula"},
	{"Imperva", "x-cdn", "incapsula"},
	{"F5 BIG-IP", "x-wa-info", ""},
	{"F5 BIG-IP", "", "bigipserver"},
	{"ModSecurity", "", "mod_security"},
	{"Wordfence", "", "wordfence"},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host + "/"
	// Benign probe + one mildly "noisy" path attackers use to trip WAFs.
	paths := []string{"/", "/?bastion_waf_probe=1", "/wp-admin/", "/.git/HEAD"}
	seen := map[string]bool{}
	var hits []string
	var blocked bool

	for _, p := range paths {
		if !t.Scope.PathAllowed(p) && p != "/" {
			continue
		}
		status, hdr, body, err := get(ctx, env, base[:len(base)-1]+p)
		if err != nil {
			continue
		}
		if status == 403 || status == 406 || status == 429 || status == 503 {
			if strings.Contains(strings.ToLower(body), "captcha") ||
				strings.Contains(strings.ToLower(body), "blocked") ||
				strings.Contains(strings.ToLower(body), "attention required") ||
				status == 403 {
				blocked = true
			}
		}
		lowBody := strings.ToLower(body)
		for _, fp := range fingerprints {
			key := fp.name
			if seen[key] {
				continue
			}
			match := false
			if fp.hdr != "" {
				for k, vs := range hdr {
					if strings.Contains(strings.ToLower(k), fp.hdr) ||
						(len(vs) > 0 && strings.Contains(strings.ToLower(vs[0]), fp.hdr)) {
						match = true
					}
				}
			}
			if fp.body != "" && strings.Contains(lowBody, fp.body) {
				match = true
			}
			if match {
				seen[key] = true
				hits = append(hits, fp.name)
			}
		}
		// Server/cdn headers
		for _, h := range []string{"Server", "Via", "X-CDN", "X-Cache"} {
			if v := hdr.Get(h); v != "" {
				hits = append(hits, h+": "+v)
			}
		}
	}
	hits = uniq(hits)

	return []scan.Finding{finding(hits, blocked)}, nil
}

func get(ctx context.Context, env *scan.Env, u string) (int, http.Header, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastionscan-Probe", "wafdetect")
	req.Header.Set("X-Bastionscan-Owner-Verified", "1")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	return resp.StatusCode, resp.Header.Clone(), string(b), nil
}

func finding(hits []string, blocked bool) scan.Finding {
	f := scan.Finding{
		ID: "active.waf", Module: "wafdetect", Category: scan.CategoryActive,
		Title: "Edge WAF / CDN presence", MaxPoints: 15,
		Reference: "https://owasp.org/www-community/controls/Web_Application_Firewall",
	}
	if len(hits) == 0 && !blocked {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 5
		f.Detail = "No common WAF/CDN fingerprints observed. Attackers prefer unprotected origins — ensure an edge control is terminating public traffic."
		f.Fix = "Place Cloudflare/AWS WAF/Akamai (or equivalent) in front of origin; block direct origin IP access."
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 15
	f.Detail = fmt.Sprintf("Edge protections detected (challenge/block=%v).", blocked)
	f.Evidence = strings.Join(hits, " · ")
	if !blocked {
		f.Detail += " No challenge page on noisy paths — tune rules for admin and sensitive routes."
	}
	return f
}

func uniq(in []string) []string {
	s := map[string]bool{}
	var o []string
	for _, x := range in {
		if s[x] {
			continue
		}
		s[x] = true
		o = append(o, x)
	}
	return o
}
