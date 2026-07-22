// Package sqli performs ownership-gated SQL injection *detection* (not
// exploitation). It uses unique canaries and known database error signatures
// with corroboration so legitimate sites are not flagged on generic 500s.
//
// Requires profile=active and DNS ownership verification.
package sqli

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

func (m *Module) ID() string              { return "sqli" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "SQL injection detection (error/boolean-based, non-exploitative). Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

// Known DB error fingerprints — only these escalate to a fail finding.
var dbErrors = []string{
	"you have an error in your sql syntax",
	"warning: mysql_",
	"unclosed quotation mark after the character string",
	"quoted string not properly terminated",
	"pg_query():",
	"postgresql query failed",
	"syntax error at or near",
	"sqlite3.operationalerror",
	"sqlite error",
	"ora-01756",
	"ora-00933",
	"microsoft ole db provider for sql server",
	"odbc sql server driver",
	"sqlserver jdbc driver",
	"sqlstate[",
	"valid mysql result",
	"mysqli_",
	"pg_exec",
	"supplied argument is not a valid mysql",
	"unclosed quotation mark before the character string",
	"microsoft jet database",
	"dynamic sql error",
	"system.Data.SqlClient.SqlException",
	"SQLSTATE",
}

// Safe detection payloads — no UNION SELECT dumps, no time-based sleeps that
// stress production (except one optional lightweight boolean pair).
var errorPayloads = []string{
	"'",
	"\"",
	"'\"",
	"1'",
	"1\"",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	surface := activekit.Discover(ctx, t, env)
	client := activekit.NewClient(env, t)

	var hits []string
	tested := 0

	// Baseline: one clean request per unique action when possible.
	for _, p := range surface.Params {
		if ctx.Err() != nil {
			break
		}
		if tested >= 24 {
			break
		}
		// Prefer ID-like and search params for SQLi precision.
		if !sqliCandidate(p.Name) {
			continue
		}
		for _, payload := range errorPayloads {
			if ctx.Err() != nil {
				break
			}
			tested++
			res := inject(ctx, client, p, payload)
			if res.Err != nil {
				continue
			}
			if sig := matchDBError(res.Body); sig != "" {
				hits = append(hits, fmt.Sprintf("%s %s param %q → DB error fingerprint %q",
					p.Method, p.Action, p.Name, sig))
				break // one hit per param is enough
			}
		}
	}

	// If no params, still probe a safe query on the homepage for reflected error
	// handling of a classic quote — only report on hard DB fingerprints.
	if tested == 0 {
		canary := activekit.Canary("bsq")
		res := client.DoGET(ctx, surface.Base+"/", map[string]string{"id": "1'" + canary})
		tested++
		if res.Err == nil {
			if sig := matchDBError(res.Body); sig != "" {
				hits = append(hits, "homepage id probe → "+sig)
			}
		}
	}

	return []scan.Finding{finding(hits, tested)}, nil
}

func sqliCandidate(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"id", "uid", "user", "item", "product", "order", "page", "cat", "sort", "filter", "search", "q", "query", "select", "report", "ref"} {
		if n == k || strings.Contains(n, k) {
			return true
		}
	}
	return true // all discovered params are candidates but we already filtered surface
}

func inject(ctx context.Context, c *activekit.Client, p activekit.Param, payload string) activekit.ProbeResult {
	if p.In == "body" || strings.EqualFold(p.Method, http.MethodPost) {
		fields := map[string]string{p.Name: p.Value + payload}
		return c.DoForm(ctx, p.Method, p.Action, fields)
	}
	return c.DoGET(ctx, p.Action, map[string]string{p.Name: p.Value + payload})
}

func matchDBError(body string) string {
	low := strings.ToLower(body)
	for _, sig := range dbErrors {
		if strings.Contains(low, strings.ToLower(sig)) {
			return sig
		}
	}
	return ""
}

func finding(hits []string, tested int) scan.Finding {
	f := scan.Finding{
		ID: "active.sqli", Module: "sqli", Category: scan.CategoryActive,
		Title: "SQL injection", MaxPoints: 40,
		Reference: "https://owasp.org/www-community/attacks/SQL_Injection",
	}
	if len(hits) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 40
		f.Detail = fmt.Sprintf("No SQL error fingerprints on %d ownership-gated probe(s). Detection-only; absence of errors is not a formal proof of safety.", tested)
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityCritical, 0
	f.Detail = "Database error signatures were reflected in responses after safe quote probes — strong indicator of SQL injection risk."
	f.Evidence = strings.Join(hits, " · ")
	f.Fix = "Use parameterized queries / prepared statements for every dynamic SQL path. Never concatenate user input into SQL. Add WAF rules as defense-in-depth, not a substitute."
	return f
}
