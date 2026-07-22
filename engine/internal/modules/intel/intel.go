// Package intel adds threat-intelligence context to a scan: where the target
// is hosted (ASN / network / country via Team Cymru), whether its IP appears on
// email/abuse blocklists (DNSBLs), and its reverse-DNS identity. It relies only
// on free, keyless DNS-based sources resolved over DNS-over-HTTPS.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module gathers reputation and hosting intelligence for the target IP.
type Module struct{}

func (m *Module) ID() string              { return "intel" }
func (m *Module) Category() scan.Category { return scan.CategoryIntel }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Threat intelligence: hosting/ASN, IP reputation on abuse blocklists, reverse DNS"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

// dnsblZones are queried for the target IP. A listing is a strong negative
// signal; a non-answer is treated as "not listed" (safer than a false positive).
var dnsblZones = []struct{ zone, name string }{
	{"zen.spamhaus.org", "Spamhaus ZEN"},
	{"bl.spamcop.net", "SpamCop"},
	{"dnsbl.sorbs.net", "SORBS"},
	{"b.barracudacentral.org", "Barracuda"},
	{"all.s5h.net", "s5h"},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	ips, err := netutil.ResolvePublicIPs(ctx, env.Resolver, t.Host)
	if err != nil {
		return []scan.Finding{{
			ID: "intel.resolve", Category: scan.CategoryIntel,
			Title: "Threat intel unavailable", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "Could not resolve a public IP for reputation lookups.", Evidence: err.Error(),
		}}, nil
	}
	// Prefer IPv4 — the Cymru and DNSBL zones are IPv4-oriented.
	ip := ips[0]
	for _, cand := range ips {
		if cand.To4() != nil {
			ip = cand
			break
		}
	}
	r := &dohResolver{env: env}

	var (
		findings []scan.Finding
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	add := func(f scan.Finding) { mu.Lock(); findings = append(findings, f); mu.Unlock() }

	wg.Add(1)
	go func() { defer wg.Done(); add(hostingFinding(ctx, r, ip)) }()
	wg.Add(1)
	go func() { defer wg.Done(); add(ptrFinding(ctx, r, ip)) }()
	wg.Add(1)
	go func() { defer wg.Done(); add(reputationFinding(ctx, r, ip)) }()
	wg.Wait()

	return findings, nil
}

// --- hosting / ASN (Team Cymru) ---------------------------------------------

func hostingFinding(ctx context.Context, r *dohResolver, ip net.IP) scan.Finding {
	f := scan.Finding{
		ID: "intel.hosting", Category: scan.CategoryIntel,
		Title: "Hosting & network", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
	}
	rev := reverseIPv4(ip)
	if rev == "" {
		f.Detail = "Hosting lookup is only available for IPv4 targets."
		return f
	}
	origin := r.txt(ctx, rev+".origin.asn.cymru.com")
	if len(origin) == 0 {
		f.Detail = "Could not determine the hosting network for this IP."
		return f
	}
	// "ASN | prefix | CC | registry | date"
	parts := splitPipe(origin[0])
	asn, prefix, cc := field(parts, 0), field(parts, 1), field(parts, 2)
	org := ""
	if asn != "" {
		if as := r.txt(ctx, "AS"+asn+".asn.cymru.com"); len(as) > 0 {
			ap := splitPipe(as[0])
			org = field(ap, len(ap)-1)
		}
	}
	f.Detail = fmt.Sprintf("Hosted on %s (AS%s), prefix %s, country %s.", orDash(org), orDash(asn), orDash(prefix), orDash(cc))
	f.Evidence = fmt.Sprintf("IP %s · AS%s %s · %s", ip, asn, org, cc)
	return f
}

// --- reverse DNS -------------------------------------------------------------

func ptrFinding(ctx context.Context, r *dohResolver, ip net.IP) scan.Finding {
	f := scan.Finding{
		ID: "intel.ptr", Category: scan.CategoryIntel,
		Title: "Reverse DNS (PTR)", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
	}
	rev := reverseIPv4(ip)
	if rev == "" {
		f.Detail = "Reverse DNS lookup is only available for IPv4 targets."
		return f
	}
	ptr := r.query(ctx, rev+".in-addr.arpa", "PTR")
	if len(ptr) == 0 {
		f.Detail = "No PTR record is configured for this IP."
		return f
	}
	f.Detail = "The IP has a reverse-DNS name."
	f.Evidence = strings.TrimSuffix(ptr[0], ".")
	return f
}

// --- reputation (DNSBLs) -----------------------------------------------------

func reputationFinding(ctx context.Context, r *dohResolver, ip net.IP) scan.Finding {
	f := scan.Finding{
		ID: "intel.reputation", Category: scan.CategoryIntel,
		Title: "IP reputation (blocklists)", MaxPoints: 20,
		Reference: "https://www.spamhaus.org/",
	}
	rev := reverseIPv4(ip)
	if rev == "" {
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "Blocklist reputation checks are only available for IPv4 targets."
		return f
	}

	var (
		mu     sync.Mutex
		listed []string
		wg     sync.WaitGroup
	)
	for _, bl := range dnsblZones {
		wg.Add(1)
		go func(zone, name string) {
			defer wg.Done()
			if a := r.query(ctx, rev+"."+zone, "A"); len(a) > 0 {
				mu.Lock()
				listed = append(listed, name)
				mu.Unlock()
			}
		}(bl.zone, bl.name)
	}
	wg.Wait()

	if len(listed) == 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 20
		f.Detail = "The target IP is not listed on the checked abuse/spam blocklists."
	} else {
		sev := scan.SeverityMedium
		if len(listed) >= 2 {
			sev = scan.SeverityHigh
		}
		f.Status, f.Severity, f.Points = scan.StatusFail, sev, 0
		f.Detail = "The target IP appears on abuse/spam blocklists, which harms deliverability and signals possible compromise."
		f.Evidence = "Listed on: " + strings.Join(listed, ", ")
		f.Fix = "Investigate for compromise/abuse, then request delisting from each blocklist."
	}
	return f
}

// --- DoH resolver ------------------------------------------------------------

type dohResolver struct{ env *scan.Env }

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func (r *dohResolver) query(ctx context.Context, name, qtype string) []string {
	endpoint := "https://dns.google/resolve?name=" + url.QueryEscape(name) + "&type=" + qtype
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", r.env.UserAgent)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.env.HTTP.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil
	}
	var dr dohResponse
	if json.Unmarshal(body, &dr) != nil {
		return nil
	}
	var out []string
	for _, a := range dr.Answer {
		out = append(out, strings.TrimSpace(a.Data))
	}
	return out
}

func (r *dohResolver) txt(ctx context.Context, name string) []string {
	var out []string
	for _, rec := range r.query(ctx, name, "TXT") {
		out = append(out, strings.Trim(rec, "\""))
	}
	return out
}

// --- helpers -----------------------------------------------------------------

func reverseIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func field(parts []string, i int) string {
	if i >= 0 && i < len(parts) {
		return parts[i]
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
