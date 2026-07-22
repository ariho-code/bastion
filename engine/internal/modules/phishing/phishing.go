// Package phishing detects scams and phishing — the question ordinary people
// actually ask: "is this link safe?" It looks for brand impersonation
// (typosquatting, homoglyphs, combosquatting, subdomain deception), wallet /
// seed-phrase harvesting, deceptive URL structure, and the keyword fingerprints
// of crypto, lottery and mobile-money scams. It runs at every scan depth,
// including the zero-touch passive tier, because a scam verdict should be
// instant and available to anyone.
package phishing

import (
	"context"
	"regexp"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module is the scam & phishing detector.
type Module struct{}

func (m *Module) ID() string              { return "phishing" }
func (m *Module) Category() scan.Category { return scan.CategoryScam }
func (m *Module) MinLevel() int           { return scan.ProfilePassive.Level }
func (m *Module) Description() string {
	return "Scam & phishing detection: brand impersonation, wallet/seed-phrase harvesting, deceptive URLs"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Run fetches the shared page (best-effort), builds a normalized input, and maps
// the assessment onto graded findings plus a consumer verdict.
func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	page := env.Page(ctx, t)

	body, title := "", ""
	if page != nil && page.Err == nil {
		body = strings.ToLower(page.Body)
		if mm := titleRe.FindStringSubmatch(page.Body); len(mm) == 2 {
			title = strings.ToLower(strings.TrimSpace(mm[1]))
		}
	}

	in := input{
		host:        t.Host,
		domain:      t.Domain,
		scheme:      strings.ToLower(t.URL.Scheme),
		hasUserinfo: t.URL.User != nil,
		path:        strings.ToLower(t.URL.EscapedPath() + "?" + t.URL.RawQuery),
		title:       title,
		body:        body,
	}

	a := assess(in)
	return findingsFor(a), nil
}

// findingsFor converts an assessment into the module's graded findings. Three
// scored findings drive the category grade; a fourth verdict finding carries the
// plain-English bottom line that the frontend and brain surface to users.
func findingsFor(a assessment) []scan.Finding {
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

	// 4. Scam-genre context (advisory, not scored) — only when something fired.
	if ev := a.scamGenreEvidence(); ev != "" {
		out = append(out, scan.Finding{
			ID: "phishing.genre", Module: "phishing", Category: scan.CategoryScam,
			Title: "Scam pattern match", Status: scan.StatusWarn, Severity: scan.SeverityMedium,
			Detail:   "The page's content matches known scam playbooks.",
			Evidence: ev,
		})
	}

	// 5. Consumer verdict — the plain-English headline (not scored).
	out = append(out, a.verdictFinding())
	return out
}

func clampPoints(p int) int {
	if p < 0 {
		return 0
	}
	return p
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
