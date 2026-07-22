// Package exposure probes for sensitive files and endpoints that should never
// be publicly reachable — leaked VCS metadata, environment files, backups,
// framework debug/admin surfaces. Every check is a plain GET of a well-known
// path; a soft-404 baseline and per-path content validators keep false
// positives out.
package exposure

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module checks for exposed sensitive paths. Deep profile: it issues extra
// requests beyond the landing page, but only safe GETs of public URLs.
type Module struct{}

func (m *Module) ID() string              { return "exposure" }
func (m *Module) Category() scan.Category { return scan.CategoryDisclosure }
func (m *Module) MinLevel() int           { return scan.ProfileDeep.Level }
func (m *Module) Description() string {
	return "Probes for exposed sensitive files: .git, .env, backups, debug/admin endpoints"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

const (
	checkConcurrency = 10
	maxProbeBody     = 64 << 10
)

// check describes a sensitive path and how to confirm it is really exposed.
// validate receives the HTTP status, a capped body, and the content-type, and
// must return true only when the response genuinely proves exposure.
type check struct {
	path     string
	title    string
	severity scan.Severity
	fix      string
	validate func(status int, body, contentType string) bool
}

func containsAll(body string, subs ...string) bool {
	for _, s := range subs {
		if !strings.Contains(body, s) {
			return false
		}
	}
	return true
}
func notHTML(ct, body string) bool {
	return !strings.Contains(ct, "html") && !strings.Contains(strings.ToLower(body), "<!doctype html") && !strings.Contains(strings.ToLower(body), "<html")
}

var checks = []check{
	{".git/config", "Exposed Git repository", scan.SeverityCritical,
		"Block access to .git/ at the web server; deploy build artifacts, not the repo.",
		func(s int, b, ct string) bool { return s == 200 && containsAll(b, "[core]") }},
	{".env", "Exposed environment file", scan.SeverityCritical,
		"Never serve .env; move secrets out of the web root and rotate any leaked keys.",
		func(s int, b, ct string) bool {
			return s == 200 && notHTML(ct, b) && (strings.Contains(b, "=") && (strings.Contains(b, "APP_") || strings.Contains(b, "DB_") || strings.Contains(b, "SECRET") || strings.Contains(b, "KEY") || strings.Contains(b, "PASSWORD")))
		}},
	{".svn/entries", "Exposed SVN metadata", scan.SeverityHigh,
		"Block access to .svn/ directories.",
		func(s int, b, ct string) bool { return s == 200 && notHTML(ct, b) }},
	{".DS_Store", "Exposed .DS_Store", scan.SeverityLow,
		"Remove .DS_Store files from the web root; they reveal directory structure.",
		func(s int, b, ct string) bool { return s == 200 && strings.Contains(b, "Bud1") }},
	{"wp-config.php.bak", "Exposed WordPress config backup", scan.SeverityCritical,
		"Delete backup copies of config files from the web root.",
		func(s int, b, ct string) bool { return s == 200 && strings.Contains(b, "DB_PASSWORD") }},
	{"config.php.bak", "Exposed PHP config backup", scan.SeverityCritical,
		"Delete backup copies of config files from the web root.",
		func(s int, b, ct string) bool { return s == 200 && notHTML(ct, b) && strings.Contains(b, "<?php") }},
	{"phpinfo.php", "Exposed phpinfo()", scan.SeverityHigh,
		"Remove phpinfo() pages; they leak paths, versions and configuration.",
		func(s int, b, ct string) bool { return s == 200 && containsAll(b, "phpinfo()") || (s == 200 && strings.Contains(b, "PHP Version") && strings.Contains(b, "Configuration")) }},
	{"server-status", "Exposed Apache server-status", scan.SeverityMedium,
		"Restrict mod_status to localhost.",
		func(s int, b, ct string) bool { return s == 200 && strings.Contains(b, "Apache Server Status") }},
	{"actuator/health", "Exposed Spring Boot Actuator", scan.SeverityHigh,
		"Secure or disable Actuator endpoints; never expose them unauthenticated.",
		func(s int, b, ct string) bool {
			return s == 200 && strings.Contains(ct, "json") && strings.Contains(strings.ToLower(b), "status")
		}},
	{".aws/credentials", "Exposed AWS credentials", scan.SeverityCritical,
		"Never store cloud credentials in the web root; rotate any exposed keys immediately.",
		func(s int, b, ct string) bool { return s == 200 && strings.Contains(b, "aws_access_key_id") }},
	{"docker-compose.yml", "Exposed docker-compose.yml", scan.SeverityMedium,
		"Keep infrastructure files out of the web root.",
		func(s int, b, ct string) bool {
			return s == 200 && notHTML(ct, b) && (strings.Contains(b, "services:") || strings.Contains(b, "image:"))
		}},
	{".git/HEAD", "Exposed Git HEAD", scan.SeverityHigh,
		"Block access to .git/ at the web server.",
		func(s int, b, ct string) bool { return s == 200 && strings.HasPrefix(strings.TrimSpace(b), "ref:") }},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	// Base the probes on where the site actually served (scheme + host), reusing
	// the shared page fetch rather than assuming HTTPS.
	base := "https://" + t.Host
	if t.Port != "" {
		base += ":" + t.Port
	}
	if page := env.Page(ctx, t); page.Err == nil && page.FinalURL != "" {
		if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
			base = u.Scheme + "://" + u.Host
		}
	}

	// Soft-404 baseline: if a random path returns 200, the site has a catch-all
	// and we must trust only strong content validators (which we do).
	softNonce := "bastionscan-" + strconv.Itoa(len(t.Host)*7+13) + "-nope"
	catchAll := false
	if st, _, _ := get(ctx, env, base+"/"+softNonce); st == 200 {
		catchAll = true
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		exposed []check
		sem     = make(chan struct{}, checkConcurrency)
	)
	for _, c := range checks {
		wg.Add(1)
		go func(c check) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			status, body, ct := get(ctx, env, base+"/"+c.path)
			if c.validate(status, body, ct) {
				mu.Lock()
				exposed = append(exposed, c)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	return buildFindings(exposed, catchAll), nil
}

func get(ctx context.Context, env *scan.Env, url string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", env.UserAgent)
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	return resp.StatusCode, string(body), resp.Header.Get("Content-Type")
}

func buildFindings(exposed []check, catchAll bool) []scan.Finding {
	f := scan.Finding{
		ID: "disclosure.exposed-files", Category: scan.CategoryDisclosure,
		Title: "No exposed sensitive files", MaxPoints: 20,
		Reference: "https://owasp.org/www-community/vulnerabilities/Sensitive_Data_Exposure",
	}
	if len(exposed) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 20
		f.Detail = "None of the probed sensitive paths (.git, .env, backups, debug/admin endpoints) were exposed."
		if catchAll {
			f.Detail += " (Site returns a catch-all 200; results rely on content validation.)"
		}
		return []scan.Finding{f}
	}

	worst := scan.SeverityLow
	var parts []string
	for _, c := range exposed {
		parts = append(parts, "/"+c.path+" — "+c.title)
		if sevRank(c.severity) < sevRank(worst) {
			worst = c.severity
		}
	}
	f.Title = "Exposed sensitive files"
	f.Status, f.Severity, f.Points = scan.StatusFail, worst, 0
	f.Detail = "Sensitive files or endpoints are publicly reachable and may leak source code, secrets, or internal state."
	f.Evidence = strings.Join(parts, " · ")
	f.Fix = exposed[0].fix
	return []scan.Finding{f}
}

func sevRank(s scan.Severity) int {
	switch s {
	case scan.SeverityCritical:
		return 0
	case scan.SeverityHigh:
		return 1
	case scan.SeverityMedium:
		return 2
	case scan.SeverityLow:
		return 3
	default:
		return 4
	}
}
