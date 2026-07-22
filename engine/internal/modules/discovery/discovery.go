// Package discovery performs active content discovery — enumerating hidden or
// forgotten attack surface: admin panels, API and documentation endpoints,
// backup archives, and monitoring/debug consoles. It probes a curated wordlist
// and confirms each hit with content validators plus a soft-404 baseline, so a
// catch-all site doesn't produce phantom results.
//
// Because it issues many speculative requests that can look like an attack and
// trip WAFs or rate limits, it is an Active-tier module: it only runs against
// targets whose ownership the caller has verified (see the verify package).
package discovery

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module enumerates additional attack surface. Active tier (ownership-gated).
type Module struct{}

func (m *Module) ID() string              { return "discovery" }
func (m *Module) Category() scan.Category { return scan.CategorySurface }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Active content discovery: admin panels, API/doc endpoints, backup archives, monitoring consoles. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

const (
	probeConcurrency = 12
	maxProbeBody     = 48 << 10
)

// group ranks discovered surface by how much its exposure matters.
type group string

const (
	groupBackup  group = "backup"  // archives / DB dumps — real data exposure
	groupAdmin   group = "admin"   // admin & auth panels — sensitive surface
	groupMonitor group = "monitor" // dashboards / debug / metrics — leaks internals
	groupAPI     group = "api"     // API and doc surfaces — reconnaissance value
)

// probe is one candidate path and how to confirm it is genuinely present.
type probe struct {
	path    string
	label   string
	group   group
	confirm func(r resp) bool
}

type resp struct {
	status int
	body   string
	ct     string
}

// protectedOrBody accepts 401/403 (the resource exists but is guarded) or a 200
// whose body satisfies the content check — the pattern that keeps precision high
// even on catch-all sites.
func protectedOrBody(check func(r resp) bool) func(r resp) bool {
	return func(r resp) bool {
		if r.status == 401 || r.status == 403 {
			return true
		}
		return r.status == 200 && check(r)
	}
}

func bodyHasAny(subs ...string) func(r resp) bool {
	return func(r resp) bool {
		b := strings.ToLower(r.body)
		for _, s := range subs {
			if strings.Contains(b, s) {
				return true
			}
		}
		return false
	}
}

func nonHTMLBody(check func(r resp) bool) func(r resp) bool {
	return func(r resp) bool {
		if strings.Contains(strings.ToLower(r.ct), "html") {
			return false
		}
		return check(r)
	}
}

var probes = []probe{
	// --- backup archives & database dumps (highest impact) ------------------
	{"backup.zip", "backup.zip archive", groupBackup, nonHTMLBody(func(r resp) bool { return r.status == 200 && strings.HasPrefix(r.body, "PK") })},
	{"backup.tar.gz", "backup.tar.gz archive", groupBackup, nonHTMLBody(func(r resp) bool { return r.status == 200 && len(r.body) > 0 && r.body[0] == 0x1f })},
	{"www.zip", "www.zip site archive", groupBackup, nonHTMLBody(func(r resp) bool { return r.status == 200 && strings.HasPrefix(r.body, "PK") })},
	{"database.sql", "database.sql dump", groupBackup, nonHTMLBody(bodyHasAny("insert into", "create table", "-- mysql dump", "drop table"))},
	{"dump.sql", "dump.sql database dump", groupBackup, nonHTMLBody(bodyHasAny("insert into", "create table", "-- mysql dump", "drop table"))},
	{"backup.sql", "backup.sql database dump", groupBackup, nonHTMLBody(bodyHasAny("insert into", "create table", "drop table"))},

	// --- admin & auth panels -----------------------------------------------
	{"admin", "admin panel", groupAdmin, protectedOrBody(bodyHasAny("login", "password", "sign in", "dashboard", "administration"))},
	{"administrator", "administrator panel", groupAdmin, protectedOrBody(bodyHasAny("login", "password", "joomla", "administration"))},
	{"wp-admin/", "WordPress admin", groupAdmin, protectedOrBody(bodyHasAny("wordpress", "wp-login", "user_login", "password"))},
	{"phpmyadmin/", "phpMyAdmin console", groupAdmin, protectedOrBody(bodyHasAny("phpmyadmin", "pma_", "server_databases"))},
	{"adminer.php", "Adminer database console", groupAdmin, protectedOrBody(bodyHasAny("adminer", "login-form", "sql command"))},
	{"manager/html", "Tomcat Manager", groupAdmin, protectedOrBody(bodyHasAny("tomcat", "manager", "unauthorized"))},
	{"user/login", "Drupal/CMS login", groupAdmin, protectedOrBody(bodyHasAny("login", "password", "username"))},

	// --- monitoring / debug / dashboards -----------------------------------
	{"actuator", "Spring Boot Actuator index", groupMonitor, func(r resp) bool {
		return r.status == 200 && strings.Contains(strings.ToLower(r.ct), "json") && strings.Contains(r.body, "_links")
	}},
	{"actuator/env", "Actuator /env (config & secrets)", groupMonitor, func(r resp) bool {
		return r.status == 200 && strings.Contains(strings.ToLower(r.ct), "json") && bodyHasAny("propertysources", "systemproperties")(r)
	}},
	{"metrics", "Prometheus metrics", groupMonitor, nonHTMLBody(bodyHasAny("# help", "# type", "process_cpu"))},
	{"debug/default/view", "Yii debug toolbar", groupMonitor, protectedOrBody(bodyHasAny("yii", "debugger", "stack trace"))},
	{"_profiler", "Symfony profiler", groupMonitor, protectedOrBody(bodyHasAny("symfony", "profiler", "web debug toolbar"))},
	{"telescope/requests", "Laravel Telescope", groupMonitor, protectedOrBody(bodyHasAny("telescope", "laravel"))},

	// --- API & documentation surfaces --------------------------------------
	{"graphql", "GraphQL endpoint", groupAPI, func(r resp) bool {
		return (r.status == 200 || r.status == 400) && bodyHasAny("\"data\"", "\"errors\"", "must provide query", "graphql")(r)
	}},
	{"swagger-ui.html", "Swagger UI", groupAPI, protectedOrBody(bodyHasAny("swagger", "swagger-ui"))},
	{"swagger/index.html", "Swagger UI", groupAPI, protectedOrBody(bodyHasAny("swagger", "swagger-ui"))},
	{"openapi.json", "OpenAPI schema", groupAPI, func(r resp) bool { return r.status == 200 && bodyHasAny("\"openapi\"", "\"swagger\"", "\"paths\"")(r) }},
	{"api-docs", "API documentation", groupAPI, func(r resp) bool { return r.status == 200 && bodyHasAny("\"openapi\"", "\"swagger\"", "\"paths\"")(r) }},
	{"api/v1", "Versioned API root", groupAPI, func(r resp) bool {
		return (r.status == 200 || r.status == 401) && (strings.Contains(strings.ToLower(r.ct), "json") || r.status == 401)
	}},
	{".well-known/openid-configuration", "OpenID Connect discovery", groupAPI, func(r resp) bool { return r.status == 200 && bodyHasAny("authorization_endpoint", "issuer")(r) }},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host
	if t.Port != "" {
		base += ":" + t.Port
	}
	if page := env.Page(ctx, t); page.Err == nil && page.FinalURL != "" {
		if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
			base = u.Scheme + "://" + u.Host
		}
	}

	// Soft-404 baseline: some sites answer 200 to everything. We record that and
	// let the per-probe content validators (not the bare status) decide.
	nonce := "bastionscan-disco-" + strconv.Itoa(len(t.Host)*11+7)
	baseStatus, _, _ := get(ctx, env, base+"/"+nonce)
	catchAll := baseStatus == 200

	type hit struct {
		g     group
		label string
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		hits []hit
		sem  = make(chan struct{}, probeConcurrency)
	)
	for _, p := range probes {
		wg.Add(1)
		go func(p probe) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			st, body, ct := get(ctx, env, base+"/"+p.path)
			if p.confirm(resp{status: st, body: body, ct: ct}) {
				mu.Lock()
				hits = append(hits, hit{p.group, p.label})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	byGroup := map[group][]string{}
	for _, h := range hits {
		byGroup[h.g] = append(byGroup[h.g], h.label)
	}
	return buildFindings(byGroup, catchAll), nil
}

func get(ctx context.Context, env *scan.Env, u string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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

// groupMeta describes how each discovered group is graded and explained.
var groupMeta = []struct {
	g        group
	title    string
	status   scan.Status
	severity scan.Severity
	detail   string
	fix      string
}{
	{groupBackup, "Backup / database archive exposed", scan.StatusFail, scan.SeverityHigh,
		"A downloadable backup archive or database dump is publicly reachable — a direct leak of source code, data, or credentials.",
		"Remove archives and dumps from the web root; store backups off the public server."},
	{groupMonitor, "Monitoring / debug console reachable", scan.StatusWarn, scan.SeverityMedium,
		"A monitoring, debug, or profiler endpoint is reachable and can leak configuration, secrets, or internal state.",
		"Restrict these endpoints to internal networks or authenticated operators."},
	{groupAdmin, "Administrative interface reachable", scan.StatusWarn, scan.SeverityMedium,
		"An administrative or authentication panel is publicly reachable. Even when protected, it should be IP-restricted or hidden to shrink the attack surface.",
		"Put admin panels behind VPN/allow-lists and enforce strong auth + MFA."},
	{groupAPI, "API / documentation surface discovered", scan.StatusInfo, scan.SeverityInfo,
		"API endpoints or interactive documentation are publicly reachable. This is often intentional, but it maps your API surface for an attacker.",
		"Ensure documentation doesn't expose internal or unreleased endpoints; require auth where appropriate."},
}

func buildFindings(byGroup map[group][]string, catchAll bool) []scan.Finding {
	var out []scan.Finding
	for _, meta := range groupMeta {
		labels := byGroup[meta.g]
		if len(labels) == 0 {
			continue
		}
		sort.Strings(labels)
		f := scan.Finding{
			ID: "surface.discovery." + string(meta.g), Category: scan.CategorySurface,
			Title: meta.title, Status: meta.status, Severity: meta.severity,
			Detail: meta.detail, Fix: meta.fix,
			Evidence: strings.Join(labels, " · "),
		}
		out = append(out, f)
	}

	if len(out) == 0 {
		detail := "Content discovery found no additional admin, API, backup, or monitoring surface beyond the main site."
		if catchAll {
			detail += " (The site returns a catch-all response; results rely on content validation.)"
		}
		return []scan.Finding{{
			ID: "surface.discovery", Category: scan.CategorySurface,
			Title: "No hidden attack surface discovered", Status: scan.StatusPass, Severity: scan.SeverityInfo,
			Detail: detail, MaxPoints: 8, Points: 8,
		}}
	}
	return out
}
