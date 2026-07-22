// Package vertical applies industry-specific Active checks for ownership-verified
// targets: banking, ecommerce, SaaS, and scam/fraud surface. Precision comes
// from path discovery + strong content/header fingerprints — not noisy 404 lists.
package vertical

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "vertical" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Industry vertical packs: banking, ecommerce, SaaS, scam/fraud surface. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

type probe struct {
	path    string
	label   string
	critical bool
	confirm func(status int, body, ct string) bool
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	v := t.Scope.NormalizedVertical()
	probes := probesFor(v)
	base := "https://" + t.Host

	var (
		mu   sync.Mutex
		hits []string
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 6)
	)
	for _, p := range probes {
		if !t.Scope.PathAllowed(p.path) {
			continue
		}
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			status, body, ct, err := get(ctx, env, base+p.path)
			if err != nil {
				return
			}
			if p.confirm(status, body, ct) {
				mu.Lock()
				hits = append(hits, fmt.Sprintf("%s (%s) → HTTP %d", p.path, p.label, status))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	return []scan.Finding{finding(v, hits, len(probes))}, nil
}

func probesFor(vertical string) []probe {
	// Shared high-value paths across verticals.
	common := []probe{
		{path: "/.env", label: "env leak", critical: true, confirm: secretFile},
		{path: "/.git/HEAD", label: "git exposure", critical: true, confirm: gitHead},
		{path: "/server-status", label: "apache status", critical: false, confirm: bodyHas("server version", "cpu usage")},
		{path: "/debug", label: "debug endpoint", critical: false, confirm: bodyHas("traceback", "stack trace", "debug")},
		{path: "/actuator/health", label: "spring actuator", critical: false, confirm: bodyHas(`"status"`, "UP", "DOWN")},
		{path: "/actuator/env", label: "spring env", critical: true, confirm: bodyHas("propertySources", "systemEnvironment")},
		{path: "/graphql", label: "graphql", critical: false, confirm: graphqlLike},
		{path: "/api/graphql", label: "graphql api", critical: false, confirm: graphqlLike},
	}

	switch vertical {
	case "banking":
		return append(common, []probe{
			{path: "/admin", label: "admin panel", critical: true, confirm: loginish},
			{path: "/backoffice", label: "backoffice", critical: true, confirm: loginish},
			{path: "/transfer", label: "transfer surface", critical: false, confirm: bodyHas("transfer", "beneficiary", "amount")},
			{path: "/api/v1/accounts", label: "accounts API", critical: true, confirm: jsonOrAuth},
			{path: "/api/v1/transactions", label: "transactions API", critical: true, confirm: jsonOrAuth},
			{path: "/open-banking", label: "open banking", critical: false, confirm: bodyHas("oauth", "consent", "psd2", "open banking")},
			{path: "/.well-known/openid-configuration", label: "OIDC discovery", critical: false, confirm: bodyHas("issuer", "authorization_endpoint")},
			{path: "/swagger", label: "api docs", critical: false, confirm: swagger},
			{path: "/swagger-ui.html", label: "swagger ui", critical: false, confirm: swagger},
			{path: "/api/docs", label: "api docs", critical: false, confirm: swagger},
		}...)
	case "ecommerce":
		return append(common, []probe{
			{path: "/admin", label: "store admin", critical: true, confirm: loginish},
			{path: "/wp-admin", label: "wp admin", critical: true, confirm: loginish},
			{path: "/cart", label: "cart", critical: false, confirm: bodyHas("cart", "checkout", "quantity")},
			{path: "/checkout", label: "checkout", critical: false, confirm: bodyHas("checkout", "payment", "shipping")},
			{path: "/api/orders", label: "orders API", critical: true, confirm: jsonOrAuth},
			{path: "/api/customers", label: "customers API", critical: true, confirm: jsonOrAuth},
			{path: "/api/products", label: "products API", critical: false, confirm: jsonOrAuth},
			{path: "/graphql", label: "storefront graphql", critical: false, confirm: graphqlLike},
			{path: "/store-config.json", label: "store config", critical: true, confirm: bodyHas("apiKey", "storeId", "magento")},
			{path: "/phpinfo.php", label: "phpinfo", critical: true, confirm: bodyHas("php version", "phpinfo()")},
		}...)
	case "saas":
		return append(common, []probe{
			{path: "/admin", label: "admin", critical: true, confirm: loginish},
			{path: "/dashboard", label: "dashboard", critical: false, confirm: bodyHas("dashboard", "workspace", "team")},
			{path: "/api/v1/users", label: "users API", critical: true, confirm: jsonOrAuth},
			{path: "/api/v1/orgs", label: "orgs API", critical: true, confirm: jsonOrAuth},
			{path: "/api/v1/tenants", label: "tenants API", critical: true, confirm: jsonOrAuth},
			{path: "/.well-known/openid-configuration", label: "OIDC", critical: false, confirm: bodyHas("issuer", "token_endpoint")},
			{path: "/metrics", label: "metrics", critical: false, confirm: bodyHas("# HELP", "prometheus")},
			{path: "/api/swagger.json", label: "openapi", critical: false, confirm: swagger},
			{path: "/v1/graphql", label: "graphql", critical: false, confirm: graphqlLike},
			{path: "/invites", label: "invite flow", critical: false, confirm: bodyHas("invite", "accept invitation")},
		}...)
	case "scam":
		// For owners of anti-fraud / brand-protection infrastructure — probe
		// common phishing-kit leftovers if they host takeovers.
		return append(common, []probe{
			{path: "/wp-login.php", label: "wp login", critical: false, confirm: loginish},
			{path: "/admin/login", label: "admin login", critical: false, confirm: loginish},
			{path: "/config.json", label: "config dump", critical: true, confirm: bodyHas("password", "api_key", "secret")},
			{path: "/backup.zip", label: "backup archive", critical: true, confirm: nonHTML200},
			{path: "/db.sql", label: "sql dump", critical: true, confirm: bodyHas("create table", "insert into")},
		}...)
	default:
		return common
	}
}

func get(ctx context.Context, env *scan.Env, rawURL string) (int, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Bastionscan-Probe", "vertical")
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
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type"), nil
}

func secretFile(status int, body, _ string) bool {
	if status != 200 {
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "app_key=") || strings.Contains(low, "db_password=") ||
		strings.Contains(low, "aws_secret") || strings.Contains(low, "secret_key=")
}

func gitHead(status int, body, _ string) bool {
	return status == 200 && strings.HasPrefix(strings.TrimSpace(body), "ref:")
}

func bodyHas(subs ...string) func(int, string, string) bool {
	return func(status int, body, _ string) bool {
		if status != 200 && status != 401 && status != 403 {
			return false
		}
		if status == 401 || status == 403 {
			return true // exists but protected — still surface
		}
		low := strings.ToLower(body)
		for _, s := range subs {
			if strings.Contains(low, strings.ToLower(s)) {
				return true
			}
		}
		return false
	}
}

func loginish(status int, body, _ string) bool {
	if status == 401 || status == 403 {
		return true
	}
	if status != 200 {
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "password") && (strings.Contains(low, "login") || strings.Contains(low, "sign in") || strings.Contains(low, "username"))
}

func jsonOrAuth(status int, body, ct string) bool {
	if status == 401 || status == 403 {
		return true
	}
	if status != 200 {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "json") || strings.HasPrefix(strings.TrimSpace(body), "{") || strings.HasPrefix(strings.TrimSpace(body), "[")
}

func graphqlLike(status int, body, _ string) bool {
	if status != 200 && status != 400 {
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "graphql") || strings.Contains(low, `"errors"`) || strings.Contains(low, "__schema")
}

func swagger(status int, body, _ string) bool {
	if status != 200 {
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "swagger") || strings.Contains(low, "openapi") || strings.Contains(low, `"paths"`)
}

func nonHTML200(status int, body, ct string) bool {
	if status != 200 {
		return false
	}
	return !strings.Contains(strings.ToLower(ct), "html") && len(body) > 0
}

func finding(vertical string, hits []string, probed int) scan.Finding {
	f := scan.Finding{
		ID: "active.vertical", Module: "vertical", Category: scan.CategoryActive,
		Title: fmt.Sprintf("Vertical surface (%s)", vertical), MaxPoints: 25,
		Reference: "https://owasp.org/www-project-application-security-verification-standard/",
	}
	if len(hits) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 25
		f.Detail = fmt.Sprintf("No high-risk %s surface paths confirmed across %d probes.", vertical, probed)
		return f
	}
	// Critical path hits escalate severity.
	sev := scan.SeverityMedium
	for _, h := range hits {
		if strings.Contains(h, "env") || strings.Contains(h, "git") || strings.Contains(h, "sql") ||
			strings.Contains(h, "actuator/env") || strings.Contains(h, "backup") {
			sev = scan.SeverityCritical
			break
		}
		if strings.Contains(h, "admin") || strings.Contains(h, "API") || strings.Contains(h, "api") {
			sev = scan.SeverityHigh
		}
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, sev, 0
	f.Detail = fmt.Sprintf("%d industry-relevant path(s) exposed or protected-but-present for vertical %q.", len(hits), vertical)
	f.Evidence = strings.Join(hits, " · ")
	f.Fix = "Remove debug/admin surfaces from production, require SSO+MFA for backoffice, never expose .env/.git, and put APIs behind authz with least privilege."
	return f
}
