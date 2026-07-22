// Package phishing detects scams and phishing — the question ordinary people
// actually ask: "is this link safe?" It looks for brand impersonation
// (typosquatting, homoglyphs, combosquatting, subdomain deception), wallet /
// seed-phrase harvesting, deceptive URL structure, domain age & multi-source
// reputation, lexical scam-domain patterns, and the keyword fingerprints of
// crypto, lottery, AI-trading and mobile-money scams. It runs at every scan
// depth, including the zero-touch passive tier, because a scam verdict should
// be instant and available to anyone.
package phishing

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module is the scam & phishing detector.
type Module struct{}

func (m *Module) ID() string              { return "phishing" }
func (m *Module) Category() scan.Category { return scan.CategoryScam }
func (m *Module) MinLevel() int           { return scan.ProfilePassive.Level }
func (m *Module) Description() string {
	return "Scam & phishing detection: brand impersonation, wallet harvesting, domain reputation, lexical AI/crypto scam patterns"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Run fetches the shared page (best-effort), builds a normalized input, and maps
// the assessment onto graded findings plus a consumer verdict.
func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)

	body, title := "", ""
	pageFailed := false
	pageStatus := 0
	if page == nil {
		pageFailed = true
	} else if page.Err != nil {
		pageFailed = true
	} else {
		pageStatus = page.Status
		// Connection succeeded but nothing usable — still a soft reachability issue
		// for brand-new kits that park on dead backends.
		if page.Status == 0 {
			pageFailed = true
		}
		body = strings.ToLower(page.Body)
		if mm := titleRe.FindStringSubmatch(page.Body); len(mm) == 2 {
			title = strings.ToLower(strings.TrimSpace(mm[1]))
		}
	}

	nr := gatherReputation(ctx, env, t.Domain)

	// Pull hosting hint from a lightweight reverse-DNS / ASN probe only when the
	// domain looks young or lexical-scam — keeps extra DNS load off established sites.
	hostingHint := ""
	sld := secondLevel(t.Domain)
	if nr.ageDays >= 0 && nr.ageDays <= 365 || len(detectLexicalDomain(t.Domain, sld)) > 0 {
		hostingHint = hostingFingerprint(ctx, env, t.Host)
	}

	in := input{
		host:        strings.ToLower(t.Host),
		domain:      strings.ToLower(t.Domain),
		scheme:      strings.ToLower(t.URL.Scheme),
		hasUserinfo: t.URL.User != nil,
		path:        strings.ToLower(t.URL.EscapedPath() + "?" + t.URL.RawQuery),
		title:       title,
		body:        body,
		pageFailed:  pageFailed,
		pageStatus:  pageStatus,
		hostingHint: hostingHint,
		ageDays:     nr.ageDays,
	}

	a := assess(in, nr.signals...)
	return findingsFor(a, nr), nil
}

// hostingFingerprint returns a lowercase string of PTR + Cymru ASN org for the
// target's first public A record. Failures return "" (no signal).
func hostingFingerprint(ctx context.Context, env *scan.Env, host string) string {
	ips, err := env.Resolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	ip := ips[0]
	rev := reverseIPv4(ip)
	if rev == "" {
		return ""
	}
	var parts []string
	if ptrs, err := env.Resolver.LookupAddr(ctx, ip.String()); err == nil {
		for _, p := range ptrs {
			parts = append(parts, strings.ToLower(strings.TrimSuffix(p, ".")))
		}
	}
	// Team Cymru origin TXT over DoH (keyless).
	answers := netutilLookupTXT(ctx, env, rev+".origin.asn.cymru.com")
	parts = append(parts, answers...)
	if len(answers) > 0 {
		// "ASN | prefix | CC | registry | date"
		fields := strings.Split(answers[0], "|")
		if len(fields) > 0 {
			asn := strings.TrimSpace(fields[0])
			if asn != "" {
				parts = append(parts, "as"+asn)
				asAnswers := netutilLookupTXT(ctx, env, "AS"+asn+".asn.cymru.com")
				parts = append(parts, asAnswers...)
			}
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

// netutilLookupTXT resolves TXT records over DoH (keyless, SSRF-safe client).
func netutilLookupTXT(ctx context.Context, env *scan.Env, name string) []string {
	raw := netutil.LookupDoH(ctx, env.HTTP, env.UserAgent, name, "TXT")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		out = append(out, strings.Trim(r, "\""))
	}
	return out
}

func reverseIPv4(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// findingsFor converts an assessment into the module's graded findings. Scored
// findings drive the category grade; the verdict finding carries the
// plain-English bottom line that the frontend and brain surface to users.
func findingsFor(a assessment, nr netResult) []scan.Finding {
	var out []scan.Finding

	// 1. Brand impersonation (weight 45).
	imp := scan.Finding{
		ID: "phishing.impersonation", Module: "phishing", Category: scan.CategoryScam,
		Title: "Brand impersonation", MaxPoints: 45,
	}
	switch {
	case a.brand != "":
		sev := scan.SeverityHigh
		if a.reachedImpersonationWeight(40) {
			sev = scan.SeverityCritical
		}
		imp.Status, imp.Severity, imp.Points = scan.StatusFail, sev, 0
		imp.Detail = "This domain is impersonating " + a.brand + ". Legitimate " + a.brand +
			" services never use look-alike domains like this one."
		imp.Evidence = a.impersonationEvidence()
		imp.Fix = "Do not enter any login, payment or wallet details. Navigate to " + a.brand +
			" by typing its real address yourself or using a trusted bookmark."
	case a.legit:
		imp.Status, imp.Severity, imp.Points = scan.StatusPass, scan.SeverityInfo, 45
		imp.Detail = "This is a recognized, official domain — not a look-alike."
	default:
		imp.Status, imp.Severity, imp.Points = scan.StatusPass, scan.SeverityInfo, 45
		imp.Detail = "The domain does not imitate any well-known brand."
	}
	out = append(out, imp)

	// 2. Credential / wallet harvesting (weight 35).
	harv := scan.Finding{
		ID: "phishing.harvesting", Module: "phishing", Category: scan.CategoryScam,
		Title: "Credential & wallet harvesting", MaxPoints: 35,
	}
	switch {
	case a.seedHarvest:
		harv.Status, harv.Severity, harv.Points = scan.StatusFail, scan.SeverityCritical, 0
		harv.Detail = "This page asks for a wallet recovery/seed phrase or private key. No legitimate " +
			"wallet or exchange EVER asks for this — it is a crypto-draining scam that will empty your wallet."
		harv.Fix = "Close the page immediately. Never type your seed phrase anywhere. If you already entered it, " +
			"move your funds to a new wallet with a fresh seed phrase now."
	case a.passwordForm && a.brand != "":
		harv.Status, harv.Severity, harv.Points = scan.StatusFail, scan.SeverityHigh, 0
		harv.Detail = "This page collects a password while impersonating " + a.brand +
			" — a credential-phishing pattern designed to steal your account."
		harv.Fix = "Do not enter your password. Report the site and change your real " + a.brand + " password if you already did."
	default:
		harv.Status, harv.Severity, harv.Points = scan.StatusPass, scan.SeverityInfo, 35
		harv.Detail = "No wallet-draining or credential-harvesting patterns were detected."
	}
	out = append(out, harv)

	// 3. Deceptive URL / hostname structure (weight 20).
	urlF := scan.Finding{
		ID: "phishing.url", Module: "phishing", Category: scan.CategoryScam,
		Title: "Deceptive URL structure", MaxPoints: 20,
	}
	if ev := a.urlDeceptionEvidence(); ev != "" {
		w := a.urlDeceptionWeight()
		urlF.Points = clampPoints(20 - w)
		if w >= 18 {
			urlF.Status, urlF.Severity = scan.StatusFail, scan.SeverityHigh
		} else {
			urlF.Status, urlF.Severity = scan.StatusWarn, scan.SeverityMedium
		}
		urlF.Detail = "The link uses structural tricks commonly seen in scams."
		urlF.Evidence = ev
		urlF.Fix = "Treat shortened, disguised or IP-based links with suspicion; hover to confirm the real destination before clicking."
	} else {
		urlF.Status, urlF.Severity, urlF.Points = scan.StatusPass, scan.SeverityInfo, 20
		urlF.Detail = "The URL structure shows no deceptive patterns."
	}
	out = append(out, urlF)

	// 4. Domain reputation: age (RDAP) + multi-blocklist + URLhaus.
	rep := scan.Finding{
		ID: "phishing.reputation", Module: "phishing", Category: scan.CategoryScam,
		Title: "Domain reputation & age", Reference: "https://www.spamhaus.org/",
	}
	switch {
	case len(nr.blocklists) > 0:
		rep.MaxPoints, rep.Points = 25, 0
		rep.Status, rep.Severity = scan.StatusFail, scan.SeverityCritical
		rep.Detail = "This domain is on reputable abuse/phishing/malware blocklists — a strong indicator it is already known to be malicious."
		rep.Evidence = "Listed on: " + strings.Join(nr.blocklists, ", ")
		if nr.regDate != "" {
			rep.Evidence += " · Registered " + nr.regDate
		}
		rep.Fix = "Do not interact with this site. If it is your own domain, investigate for compromise and request delisting."
	case nr.ageDays >= 0 && nr.ageDays <= 30:
		rep.MaxPoints, rep.Points = 25, 0
		rep.Status, rep.Severity = scan.StatusFail, scan.SeverityHigh
		rep.Detail = "This domain was registered very recently (" + humanAge(nr.ageDays) + "). The vast majority of phishing and scam domains are only days or weeks old."
		rep.Evidence = "Registered " + nr.regDate
		rep.Fix = "Be extremely cautious with brand-new domains asking for logins, payments or wallet access."
	case nr.ageDays >= 0 && nr.ageDays <= 90:
		rep.MaxPoints, rep.Points = 25, 8
		rep.Status, rep.Severity = scan.StatusWarn, scan.SeverityMedium
		rep.Detail = "This domain is fairly new (" + humanAge(nr.ageDays) + "). Newness alone isn't proof of a scam, but stay alert — especially for investment or crypto offers."
		rep.Evidence = "Registered " + nr.regDate
	case nr.ageDays >= 0 && nr.ageDays <= 180:
		rep.MaxPoints, rep.Points = 25, 14
		rep.Status, rep.Severity = scan.StatusWarn, scan.SeverityLow
		rep.Detail = "This domain is under six months old (" + humanAge(nr.ageDays) + "). Many AI-trading and investment scams operate on domains this age."
		rep.Evidence = "Registered " + nr.regDate
	case nr.ageDays > 180:
		rep.MaxPoints, rep.Points = 25, 25
		rep.Status, rep.Severity = scan.StatusPass, scan.SeverityInfo
		rep.Detail = "The domain is well-established (" + humanAge(nr.ageDays) + ") and not on any checked blocklist."
		rep.Evidence = "Registered " + nr.regDate
		if nr.registrar != "" {
			rep.Evidence += " · Registrar: " + nr.registrar
		}
	default:
		rep.MaxPoints, rep.Points = 0, 0
		rep.Status, rep.Severity = scan.StatusInfo, scan.SeverityInfo
		rep.Detail = "The domain's registration age could not be determined; it is not on any checked blocklist."
	}
	out = append(out, rep)

	// 5. Lexical / kit-pattern signals (scored when present).
	if ev := a.lexicalEvidence(); ev != "" {
		sev := scan.SeverityMedium
		st := scan.StatusWarn
		if a.verdict >= verdictSuspicious {
			sev = scan.SeverityHigh
			st = scan.StatusFail
		}
		out = append(out, scan.Finding{
			ID: "phishing.lexical", Module: "phishing", Category: scan.CategoryScam,
			Title: "Suspicious domain naming", Status: st, Severity: sev,
			MaxPoints: 15, Points: 0,
			Detail:   "The domain name itself matches patterns used by disposable investment, AI-trading, and crypto-scam sites.",
			Evidence: ev,
			Fix:      "Do not invest, deposit, or connect a wallet. Verify any company through independent sources before trusting a new domain.",
		})
	}

	// 6. Reachability / hosting risk (advisory → warn when combined with youth).
	if ev := a.infraEvidence(); ev != "" {
		sev := scan.SeverityLow
		st := scan.StatusWarn
		if a.verdict >= verdictSuspicious {
			sev = scan.SeverityMedium
		}
		out = append(out, scan.Finding{
			ID: "phishing.infra", Module: "phishing", Category: scan.CategoryScam,
			Title: "Infrastructure risk signals", Status: st, Severity: sev,
			Detail:   "Hosting or reachability characteristics commonly seen on disposable scam infrastructure.",
			Evidence: ev,
		})
	}

	// 7. Scam-genre context (advisory, not scored) — only when something fired.
	if ev := a.scamGenreEvidence(); ev != "" {
		out = append(out, scan.Finding{
			ID: "phishing.genre", Module: "phishing", Category: scan.CategoryScam,
			Title: "Scam pattern match", Status: scan.StatusWarn, Severity: scan.SeverityMedium,
			Detail:   "The page's content matches known scam playbooks.",
			Evidence: ev,
		})
	}

	// 8. Consumer verdict — the plain-English headline (not scored).
	out = append(out, a.verdictFinding())
	return out
}

func clampPoints(p int) int {
	if p < 0 {
		return 0
	}
	return p
}

// humanAge renders a domain age in days as a friendly phrase for report text.
func humanAge(days int) string {
	switch {
	case days <= 1:
		return "registered today"
	case days < 14:
		return strconv.Itoa(days) + " days old"
	case days < 60:
		return strconv.Itoa(days/7) + " weeks old"
	case days < 730:
		return strconv.Itoa(days/30) + " months old"
	default:
		return strconv.Itoa(days/365) + " years old"
	}
}

// --- assessment presentation helpers ----------------------------------------

func (a assessment) reachedImpersonationWeight(min int) bool {
	for _, s := range a.signals {
		if strings.HasPrefix(s.code, "impersonation:") && s.weight >= min {
			return true
		}
	}
	return false
}

func (a assessment) impersonationEvidence() string {
	for _, s := range a.signals {
		if strings.HasPrefix(s.code, "impersonation:") {
			return s.detail
		}
	}
	return ""
}

func (a assessment) urlDeceptionEvidence() string {
	var parts []string
	for _, s := range a.signals {
		if isURLCode(s.code) {
			parts = append(parts, s.detail)
		}
	}
	return strings.Join(parts, " ")
}

func (a assessment) urlDeceptionWeight() int {
	w := 0
	for _, s := range a.signals {
		if isURLCode(s.code) {
			w += s.weight
		}
	}
	return w
}

func (a assessment) scamGenreEvidence() string {
	var parts []string
	for _, s := range a.signals {
		if strings.HasPrefix(s.code, "scam:") || s.code == "wallet-drainer" || s.code == "brand-content" {
			parts = append(parts, s.detail)
		}
	}
	return strings.Join(parts, " ")
}

func (a assessment) lexicalEvidence() string {
	var parts []string
	for _, s := range a.signals {
		if strings.HasPrefix(s.code, "lexical") {
			parts = append(parts, s.detail)
		}
	}
	return strings.Join(parts, " ")
}

func (a assessment) infraEvidence() string {
	var parts []string
	for _, s := range a.signals {
		switch s.code {
		case "unreachable", "hosting-risk":
			parts = append(parts, s.detail)
		}
	}
	return strings.Join(parts, " ")
}

func isURLCode(code string) bool {
	switch code {
	case "ip-host", "userinfo", "punycode", "deep-subdomain", "hyphenated",
		"abuse-tld", "http-login", "phishy-path":
		return true
	}
	return false
}

// verdictFinding is the module's headline: a single, unmistakable statement of
// whether the site is safe, keyed by the frontend/brain to render a banner.
func (a assessment) verdictFinding() scan.Finding {
	f := scan.Finding{
		ID: "phishing.verdict", Module: "phishing", Category: scan.CategoryScam,
		Title: "Scam verdict: " + a.verdict.label(),
	}
	switch a.verdict {
	case verdictDangerous:
		f.Status, f.Severity = scan.StatusFail, scan.SeverityCritical
		f.Detail = "DANGEROUS — this site shows strong signs of being a phishing or crypto-draining scam. " +
			"Do not log in, pay, or connect a wallet. " + a.verdictReason()
	case verdictSuspicious:
		f.Status, f.Severity = scan.StatusFail, scan.SeverityHigh
		f.Detail = "SUSPICIOUS — this site has several red flags typical of scams. Proceed only if you are certain it is genuine. " +
			a.verdictReason()
	case verdictLow:
		f.Status, f.Severity = scan.StatusWarn, scan.SeverityLow
		f.Detail = "LOW RISK — a minor indicator was found, but nothing conclusive. Stay alert. " + a.verdictReason()
	default:
		f.Status, f.Severity = scan.StatusPass, scan.SeverityInfo
		f.Detail = "SAFE — no scam or phishing indicators were detected on this site."
	}
	return f
}

func (a assessment) verdictReason() string {
	if len(a.signals) == 0 {
		return ""
	}
	// Surface the single highest-weight reason in plain language.
	top := a.signals[0]
	for _, s := range a.signals {
		if s.weight > top.weight {
			top = s
		}
	}
	return "Main reason: " + top.detail
}
