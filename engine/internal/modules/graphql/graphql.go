// Package graphql probes GraphQL endpoints on ownership-verified targets for
// introspection exposure and overly permissive schemas — detection only.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "graphql" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "GraphQL introspection & API surface checks. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

var endpoints = []string{
	"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql",
}

// Minimal introspection query — not a data dump of business records.
const introspectQ = `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}`

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host
	var (
		found []string
		open  []string
	)
	for _, ep := range endpoints {
		if !t.Scope.PathAllowed(ep) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		status, body, ok := postJSON(ctx, env, base+ep, introspectQ)
		if !ok {
			// Try GET with query param (some servers allow it).
			status, body, ok = getQuery(ctx, env, base+ep)
		}
		if !ok {
			continue
		}
		low := strings.ToLower(body)
		if !looksGraphQL(status, low) {
			continue
		}
		found = append(found, fmt.Sprintf("%s (HTTP %d)", ep, status))
		if strings.Contains(low, `"__schema"`) || strings.Contains(low, `"querytype"`) ||
			(strings.Contains(low, `"data"`) && strings.Contains(low, `"types"`)) {
			open = append(open, ep+" allows introspection")
		}
	}

	return []scan.Finding{finding(found, open)}, nil
}

func postJSON(ctx context.Context, env *scan.Env, rawURL, body string) (int, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Bastionscan-Probe", "graphql")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b), true
}

func getQuery(ctx context.Context, env *scan.Env, rawURL string) (int, string, bool) {
	u := rawURL + "?query=%7B__typename%7D"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Accept", "application/json")
	for k, vs := range env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	return resp.StatusCode, string(b), true
}

func looksGraphQL(status int, low string) bool {
	if status >= 500 {
		return false
	}
	// JSON GraphQL responses almost always have data or errors keys.
	if strings.Contains(low, `"errors"`) || strings.Contains(low, `"data"`) {
		return true
	}
	if strings.Contains(low, "must provide an operation") || strings.Contains(low, "graphql") {
		return true
	}
	// Validate JSON shape loosely.
	var dummy map[string]any
	return json.Unmarshal([]byte(low), &dummy) == nil && (dummy["errors"] != nil || dummy["data"] != nil)
}

func finding(found, open []string) scan.Finding {
	f := scan.Finding{
		ID: "active.graphql", Module: "graphql", Category: scan.CategoryActive,
		Title: "GraphQL API security", MaxPoints: 25,
		Reference: "https://owasp.org/www-project-graphql-security/",
	}
	if len(found) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusInfo, scan.SeverityInfo, 0
		f.MaxPoints = 0
		f.Detail = "No GraphQL endpoint responded on common paths."
		return f
	}
	if len(open) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 25
		f.Detail = fmt.Sprintf("GraphQL present (%s) but introspection appears disabled.", strings.Join(found, ", "))
		return f
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
	f.Detail = "GraphQL introspection is enabled in what appears to be a production surface — attackers can map the full schema."
	f.Evidence = strings.Join(append(found, open...), " · ")
	f.Fix = "Disable introspection in production, require auth on GraphQL, enforce query depth/cost limits, and prefer allow-listed operations."
	return f
}
