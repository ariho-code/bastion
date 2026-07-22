// Package takeover checks for dangling DNS records that enable subdomain
// takeover — a classic attacker foothold. Ownership-gated Active module.
package takeover

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

type Module struct{}

func (m *Module) ID() string              { return "takeover" }
func (m *Module) Category() scan.Category { return scan.CategoryActive }
func (m *Module) MinLevel() int           { return scan.ProfileActive.Level }
func (m *Module) Description() string {
	return "Subdomain takeover signals via dangling CNAME targets. Ownership-gated."
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" && t.Verified }

// Fingerprints of cloud hosts that are commonly left dangling after deprovision.
var danglingHints = []string{
	"github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
	"s3-website", "cloudfront.net", "azurewebsites.net", "cloudapp.azure.com",
	"trafficmanager.net", "blob.core.windows.net", "azurefd.net",
	"shopify.com", "myshopify.com", "unbouncepages.com", "pantheonsite.io",
	"wpengine.com", "fastly.net", "bitbucket.io", "gitlab.io",
	"netlify.com", "netlify.app", "vercel.app", "surge.sh",
	"readme.io", "zendesk.com", "helpjuice.com", "helpscoutdocs.com",
	"ghost.io", "ngrok.io", "cargo.site", "statuspage.io",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	// Check apex + common subdomains that orgs forget.
	hosts := []string{t.Host, "www." + t.Domain, "docs." + t.Domain, "status." + t.Domain,
		"cdn." + t.Domain, "static." + t.Domain, "assets." + t.Domain, "blog." + t.Domain,
		"help." + t.Domain, "support." + t.Domain, "dev." + t.Domain, "staging." + t.Domain}

	var risks []string
	seen := map[string]bool{}
	res := env.Resolver
	if res == nil {
		res = net.DefaultResolver
	}

	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		if ctx.Err() != nil {
			break
		}
		cname, err := res.LookupCNAME(ctx, h)
		if err != nil || cname == "" || strings.EqualFold(cname, h+".") || strings.EqualFold(cname, h) {
			continue
		}
		cname = strings.TrimSuffix(strings.ToLower(cname), ".")
		for _, hint := range danglingHints {
			if strings.Contains(cname, hint) {
				// NXDOMAIN or no A/AAAA on the name is a stronger signal.
				addrs, aerr := res.LookupHost(ctx, h)
				if aerr != nil || len(addrs) == 0 {
					risks = append(risks, fmt.Sprintf("%s → %s (no address records)", h, cname))
				} else {
					// Still note cloud CNAME for review (weaker).
					risks = append(risks, fmt.Sprintf("%s → %s (cloud host — confirm still owned)", h, cname))
				}
				break
			}
		}
	}

	return []scan.Finding{finding(risks)}, nil
}

func finding(risks []string) scan.Finding {
	f := scan.Finding{
		ID: "active.takeover", Module: "takeover", Category: scan.CategoryActive,
		Title: "Subdomain takeover risk", MaxPoints: 25,
		Reference: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
	}
	if len(risks) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 25
		f.Detail = "No dangling cloud CNAME patterns detected on common hostnames."
		return f
	}
	// Escalate if any NXDOMAIN-style hits.
	sev := scan.SeverityMedium
	for _, r := range risks {
		if strings.Contains(r, "no address") {
			sev = scan.SeverityHigh
			break
		}
	}
	f.Status, f.Severity, f.Points = scan.StatusFail, sev, 0
	f.Detail = "DNS points at cloud hosts that may be claimable if the upstream resource was deleted — a common takeover path."
	f.Evidence = strings.Join(risks, " · ")
	f.Fix = "Remove stale DNS records, or reclaim the cloud resource. Prefer CNAME flattening / ALIAS only to resources you still control."
	return f
}
