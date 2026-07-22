// Package subdomains discovers a target's subdomains — the classic first step
// of attack-surface mapping. It fuses two passive/light sources: Certificate
// Transparency logs (every public cert ever issued for the domain) and a DNS
// wordlist probe, then confirms which names actually resolve.
package subdomains

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module enumerates subdomains. Deep-profile: it issues many DNS lookups and a
// CT-log query.
type Module struct{}

func (m *Module) ID() string              { return "subdomains" }
func (m *Module) Category() scan.Category { return scan.CategorySurface }
func (m *Module) MinLevel() int           { return scan.ProfileDeep.Level }
func (m *Module) Description() string {
	return "Subdomain discovery via Certificate Transparency logs and DNS wordlist, with live-resolution check"
}

// Supports skips raw-IP targets (no subdomains) and needs a registrable domain.
func (m *Module) Supports(t *scan.Target) bool {
	return t.Domain != "" && net.ParseIP(t.Host) == nil
}

const (
	maxCandidates  = 200
	maxCTNames     = 150
	resolveWorkers = 100
	lookupTimeout  = 2500 * time.Millisecond
	sampleSize     = 25
)

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	candidates := map[string]bool{}

	// Source 1: Certificate Transparency (passive, high-signal).
	for _, name := range fetchCT(ctx, env, t.Domain) {
		candidates[name] = true
	}
	// Source 2: DNS wordlist expansion.
	for _, w := range wordlist {
		candidates[w+"."+t.Domain] = true
		if len(candidates) >= maxCandidates {
			break
		}
	}

	live := resolveAll(ctx, env.Resolver, keys(candidates))
	return buildFindings(t.Domain, len(candidates), live), nil
}

// --- Certificate Transparency ------------------------------------------------

func fetchCT(ctx context.Context, env *scan.Env, domain string) []string {
	url := "https://crt.sh/?q=%25." + domain + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", env.UserAgent)
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal(data, &entries) != nil {
		return nil
	}
	suffix := "." + domain
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "*.")))
			if name == "" || seen[name] {
				continue
			}
			if name == domain || strings.HasSuffix(name, suffix) {
				seen[name] = true
				out = append(out, name)
				if len(out) >= maxCTNames {
					return out
				}
			}
		}
	}
	return out
}

// --- resolution --------------------------------------------------------------

// resolveAll checks which candidate names actually resolve, concurrently.
func resolveAll(ctx context.Context, res *net.Resolver, names []string) []string {
	if res == nil {
		res = net.DefaultResolver
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		live []string
		sem  = make(chan struct{}, resolveWorkers)
	)
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			// Per-lookup deadline so a slow NXDOMAIN can't drag the whole scan.
			lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
			defer cancel()
			if addrs, err := res.LookupHost(lctx, name); err == nil && len(addrs) > 0 {
				mu.Lock()
				live = append(live, name)
				mu.Unlock()
			}
		}(name)
	}
	wg.Wait()
	sort.Strings(live)
	return live
}

// --- findings ----------------------------------------------------------------

// sensitivePrefixes are subdomain labels that typically indicate extra,
// higher-risk attack surface (non-production, admin, or internal tooling).
var sensitivePrefixes = map[string]bool{
	"dev": true, "development": true, "staging": true, "stage": true, "test": true,
	"testing": true, "uat": true, "qa": true, "sandbox": true, "demo": true, "beta": true,
	"admin": true, "administrator": true, "panel": true, "cpanel": true, "whm": true,
	"vpn": true, "jenkins": true, "ci": true, "gitlab": true, "git": true, "jira": true,
	"confluence": true, "grafana": true, "kibana": true, "prometheus": true, "phpmyadmin": true,
	"portainer": true, "backup": true, "db": true, "database": true, "internal": true,
	"intranet": true, "old": true, "legacy": true,
}

func buildFindings(domain string, discovered int, live []string) []scan.Finding {
	inv := scan.Finding{
		ID: "surface.subdomains", Category: scan.CategorySurface,
		Title: "Subdomain discovery", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
	}
	if len(live) == 0 {
		inv.Detail = fmt.Sprintf("Discovered %d candidate name(s) for %s; none resolved live.", discovered, domain)
		return []scan.Finding{inv}
	}
	inv.Detail = fmt.Sprintf("Discovered %d candidate name(s); %d resolve live.", discovered, len(live))
	inv.Evidence = strings.Join(sample(live, sampleSize), ", ")

	// Flag sensitive subdomains as expanded attack surface.
	var sensitive []string
	for _, name := range live {
		label := strings.TrimSuffix(name, "."+domain)
		first := label
		if i := strings.Index(label, "."); i >= 0 {
			first = label[:i]
		}
		if sensitivePrefixes[first] {
			sensitive = append(sensitive, name)
		}
	}

	sens := scan.Finding{
		ID: "surface.sensitive-subdomains", Category: scan.CategorySurface,
		Title: "No sensitive subdomains exposed", MaxPoints: 10,
	}
	if len(sensitive) > 0 {
		sens.Title = "Sensitive subdomains exposed"
		sens.Status, sens.Severity, sens.Points = scan.StatusWarn, scan.SeverityMedium, 4
		sens.Detail = "Non-production, admin, or internal-tooling subdomains are publicly resolvable — extra attack surface that is often less hardened."
		sens.Evidence = strings.Join(sample(sensitive, sampleSize), ", ")
		sens.Fix = "Restrict dev/staging/admin hosts to a VPN or IP allowlist; remove stale DNS records."
	} else {
		sens.Status, sens.Severity, sens.Points = scan.StatusPass, scan.SeverityInfo, 10
		sens.Detail = "No obviously sensitive (dev/staging/admin/internal) subdomains were found resolving publicly."
	}
	return []scan.Finding{inv, sens}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sample(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("…+%d more", len(s)-n))
}

// wordlist is a compact set of common subdomain labels for DNS probing.
var wordlist = []string{
	"www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ns1", "ns2",
	"api", "api-dev", "dev", "development", "staging", "stage", "test", "uat",
	"sandbox", "beta", "demo", "admin", "administrator", "portal", "dashboard",
	"panel", "cpanel", "whm", "vpn", "remote", "gateway", "git", "gitlab",
	"jenkins", "ci", "jira", "confluence", "wiki", "grafana", "kibana", "status",
	"monitor", "backup", "db", "database", "internal", "intranet", "secure",
	"login", "sso", "auth", "app", "apps", "mobile", "cdn", "static", "assets",
	"img", "media", "files", "download", "docs", "support", "help", "blog",
	"shop", "store", "pay", "old", "phpmyadmin", "portainer", "grafana",
}
