// Package hostinject tests Host-header and password-reset style injection
// vectors used in real attacks (cache poisoning, password-reset poisoning).
// Detection only — ownership-gated.
package hostinject

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

func (m *Module) ID() string              { return "hostinject" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Host header injection / poisoning surface detection. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

const canaryHost = "bastion-host-canary.example"

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	url := "https://" + t.Host + "/"
	if !t.Scope.PathAllowed("/") {
		return []scan.Finding{info("Root path excluded by scope.")}, nil
	}

	// Absolute-form Host override via Host header (classic).
	status, body, loc, err := getWithHost(ctx, env, url, canaryHost)
	if err != nil {
		return []scan.Finding{info("Host injection probe failed: " + err.Error())}, nil
	}
	reflected := strings.Contains(strings.ToLower(body), canaryHost) ||
		strings.Contains(strings.ToLower(loc), canaryHost)

	// X-Forwarded-Host variant many apps trust.
	status2, body2, loc2, err2 := getWithExtra(ctx, env, url, map[string]string{
		"X-Forwarded-Host": canaryHost,
		"X-Host":           canaryHost,
		"Forwarded":        "host=" + canaryHost,
	})
	_ = status2
	if err2 == nil {
		if strings.Contains(strings.ToLower(body2), canaryHost) ||
			strings.Contains(strings.ToLower(loc2), canaryHost) {
			reflected = true
		}
	}

	return []scan.Finding{finding(reflected, status, loc)}, nil
}

func getWithHost(ctx context.Context, env *scan.Env, rawURL, host string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Host = host
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastionscan-Probe", "hostinject")
	req.Header.Set("X-Bastionscan-Owner-Verified", "1")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 48<<10))
	return resp.StatusCode, string(b), resp.Header.Get("Location"), nil
}

func getWithExtra(ctx context.Context, env *scan.Env, rawURL string, extra map[string]string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("X-Bastionscan-Probe", "hostinject")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 48<<10))
	return resp.StatusCode, string(b), resp.Header.Get("Location"), nil
}

func finding(reflected bool, status int, loc string) scan.Finding {
	f := scan.Finding{
		ID: "active.hostinject", Module: "hostinject", Category: scan.CategoryActive,
		Title: "Host header injection", MaxPoints: 25,
		Reference: "https://portswigger.net/web-security/host-header",
	}
	if !reflected {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 25
		f.Detail = fmt.Sprintf("Canary host not reflected in body/Location (HTTP %d). App appears to ignore untrusted Host/X-Forwarded-Host.", status)
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = "Application reflects or redirects using an attacker-controlled Host / X-Forwarded-Host canary — password-reset and cache poisoning risk."
	f.Evidence = "canary=" + canaryHost + " location=" + loc
	f.Fix = "Ignore absolute Host from clients at the edge; use a configured canonical host. Do not trust X-Forwarded-Host unless set by your own reverse proxy."
	return f
}

func info(d string) scan.Finding {
	return scan.Finding{
		ID: "active.hostinject", Module: "hostinject", Category: scan.CategoryActive,
		Title: "Host header injection", Status: scan.StatusInfo, Severity: scan.SeverityInfo, Detail: d,
	}
}
