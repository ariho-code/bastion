// Package dns audits a domain's DNS-layer security: email authentication
// (SPF, DMARC, DKIM), certificate issuance control (CAA), and zone integrity
// (DNSSEC). It resolves everything over DNS-over-HTTPS so it can read record
// types — CAA, DS — and the DNSSEC AD flag that the Go stdlib resolver omits.
package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module performs DNS/email security analysis via DoH.
type Module struct{}

func (m *Module) ID() string              { return "dns" }
func (m *Module) Category() scan.Category { return scan.CategoryDNS }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "DNS & email security: SPF, DMARC, DKIM, CAA and DNSSEC via DNS-over-HTTPS"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Domain != "" }

// commonDKIMSelectors are probed in parallel; DKIM absence can't be proven
// without knowing the selector, so a miss is informational, not a failure.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "dkim", "mail",
	"s1", "s2", "mandrill", "sendgrid", "zoho", "protonmail", "mailchimp",
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	d := t.Domain
	r := &resolver{env: env}

	var (
		mx, spf, dmarc, caa []string
		dnssec              bool
		dkim                string
		wg                  sync.WaitGroup
	)
	run := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }

	run(func() { mx, _ = r.query(ctx, d, "MX") })
	run(func() { spf = filterPrefix(mustTXT(r.query(ctx, d, "TXT")), "v=spf1") })
	run(func() { dmarc = filterPrefix(mustTXT(r.query(ctx, "_dmarc."+d, "TXT")), "v=dmarc1") })
	run(func() { caa, _ = r.query(ctx, d, "CAA") })
	run(func() {
		ds, ad := r.query(ctx, d, "DS")
		dnssec = len(ds) > 0 || ad
	})
	run(func() { dkim = probeDKIM(ctx, r, d) })
	wg.Wait()

	hasMX := len(mx) > 0
	return []scan.Finding{
		spfFinding(spf, hasMX),
		dmarcFinding(dmarc, hasMX),
		dkimFinding(dkim),
		caaFinding(caa),
		dnssecFinding(dnssec),
		mxFinding(mx),
	}, nil
}

// --- DoH resolver ------------------------------------------------------------

type resolver struct{ env *scan.Env }

type dohResponse struct {
	Status int  `json:"Status"`
	AD     bool `json:"AD"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// query returns the record data strings for name/type and whether the answer
// was DNSSEC-authenticated (AD flag).
func (r *resolver) query(ctx context.Context, name, qtype string) ([]string, bool) {
	endpoint := "https://dns.google/resolve?do=1&name=" + url.QueryEscape(name) + "&type=" + qtype
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", r.env.UserAgent)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.env.HTTP.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, false
	}
	var dr dohResponse
	if json.Unmarshal(body, &dr) != nil {
		return nil, false
	}
	var out []string
	for _, a := range dr.Answer {
		out = append(out, unquoteTXT(a.Data))
	}
	return out, dr.AD
}

func probeDKIM(ctx context.Context, r *resolver, domain string) string {
	var (
		mu    sync.Mutex
		found string
		wg    sync.WaitGroup
		sem   = make(chan struct{}, 8)
	)
	for _, sel := range commonDKIMSelectors {
		wg.Add(1)
		go func(sel string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			recs, _ := r.query(ctx, sel+"._domainkey."+domain, "TXT")
			for _, rec := range recs {
				low := strings.ToLower(rec)
				if strings.Contains(low, "v=dkim1") || strings.Contains(low, "k=rsa") || strings.Contains(low, "p=") {
					mu.Lock()
					if found == "" {
						found = sel
					}
					mu.Unlock()
					return
				}
			}
		}(sel)
	}
	wg.Wait()
	return found
}

// --- findings ----------------------------------------------------------------

func spfFinding(spf []string, hasMX bool) scan.Finding {
	f := scan.Finding{
		ID: "dns.spf", Category: scan.CategoryDNS,
		Title: "SPF record", MaxPoints: 10,
		Reference: "https://datatracker.ietf.org/doc/html/rfc7208",
	}
	if len(spf) > 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "An SPF record declares which servers may send mail for this domain."
		f.Evidence = clip(spf[0], 160)
	} else {
		sev := scan.SeverityLow
		if hasMX {
			sev = scan.SeverityMedium
		}
		f.Status, f.Severity, f.Points = scan.StatusFail, sev, 0
		f.Detail = "No SPF record. Attackers can more easily spoof mail from this domain."
		f.Fix = "Publish a TXT record: v=spf1 include:_your_provider ~all"
	}
	return f
}

func dmarcFinding(dmarc []string, hasMX bool) scan.Finding {
	f := scan.Finding{
		ID: "dns.dmarc", Category: scan.CategoryDNS,
		Title: "DMARC policy", MaxPoints: 12,
		Reference: "https://datatracker.ietf.org/doc/html/rfc7489",
	}
	if len(dmarc) == 0 {
		sev := scan.SeverityLow
		if hasMX {
			sev = scan.SeverityMedium
		}
		f.Status, f.Severity, f.Points = scan.StatusFail, sev, 0
		f.Detail = "No DMARC record. Nothing tells receivers what to do with spoofed mail."
		f.Fix = "Publish _dmarc TXT: v=DMARC1; p=reject; rua=mailto:you@domain"
		return f
	}
	rec := strings.ToLower(dmarc[0])
	f.Evidence = clip(dmarc[0], 160)
	switch {
	case strings.Contains(rec, "p=reject"), strings.Contains(rec, "p=quarantine"):
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 12
		f.Detail = "DMARC is enforced (quarantine/reject), actively blocking spoofed mail."
	default: // p=none
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 6
		f.Detail = "DMARC is in monitor-only mode (p=none) — it reports but doesn't block spoofing."
		f.Fix = "Move to p=quarantine, then p=reject once reports look clean."
	}
	return f
}

func dkimFinding(selector string) scan.Finding {
	f := scan.Finding{
		ID: "dns.dkim", Category: scan.CategoryDNS,
		Title: "DKIM signing", MaxPoints: 6,
	}
	if selector != "" {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "A DKIM key was found, so outbound mail can be cryptographically signed."
		f.Evidence = "selector: " + selector
	} else {
		// Can't prove absence without the selector — informational only.
		f.Status, f.Severity, f.Points, f.MaxPoints = scan.StatusInfo, scan.SeverityInfo, 0, 0
		f.Detail = "No DKIM key found at common selectors (this doesn't prove DKIM is absent — the selector may be custom)."
	}
	return f
}

func caaFinding(caa []string) scan.Finding {
	f := scan.Finding{
		ID: "dns.caa", Category: scan.CategoryDNS,
		Title: "CAA record", MaxPoints: 6,
		Reference: "https://datatracker.ietf.org/doc/html/rfc8659",
	}
	if len(caa) > 0 {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 6
		f.Detail = "CAA records restrict which certificate authorities may issue for this domain."
		f.Evidence = clip(strings.Join(caa, "; "), 160)
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "No CAA record — any CA can issue a certificate for this domain."
		f.Fix = "Add a CAA record naming your CA, e.g. 0 issue \"letsencrypt.org\"."
	}
	return f
}

func dnssecFinding(enabled bool) scan.Finding {
	f := scan.Finding{
		ID: "dns.dnssec", Category: scan.CategoryDNS,
		Title: "DNSSEC", MaxPoints: 8,
	}
	if enabled {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 8
		f.Detail = "DNSSEC is enabled, cryptographically protecting DNS answers from tampering."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 0
		f.Detail = "DNSSEC is not enabled — DNS responses can be spoofed via cache poisoning."
		f.Fix = "Enable DNSSEC signing at your DNS provider and add the DS record at your registrar."
	}
	return f
}

func mxFinding(mx []string) scan.Finding {
	f := scan.Finding{
		ID: "dns.mx", Category: scan.CategoryDNS,
		Title: "Mail exchange (MX)", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
	}
	if len(mx) > 0 {
		f.Detail = fmt.Sprintf("The domain has %d MX record(s) — it receives email.", len(mx))
		f.Evidence = clip(strings.Join(mx, ", "), 160)
	} else {
		f.Detail = "No MX records — the domain does not receive email."
	}
	return f
}

// --- helpers -----------------------------------------------------------------

func mustTXT(recs []string, _ bool) []string { return recs }

func filterPrefix(recs []string, prefix string) []string {
	var out []string
	for _, r := range recs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
			out = append(out, r)
		}
	}
	return out
}

func unquoteTXT(s string) string {
	s = strings.TrimSpace(s)
	// DoH returns TXT chunks wrapped in quotes, possibly multiple concatenated.
	if strings.Contains(s, "\"") {
		s = strings.ReplaceAll(s, "\" \"", "")
		s = strings.Trim(s, "\"")
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
