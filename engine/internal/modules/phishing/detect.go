package phishing

import (
	"net"
	"strings"
)

// verdict is the consumer-facing bottom line: is this safe to interact with?
type verdict int

const (
	verdictClean      verdict = iota // no meaningful scam indicators
	verdictLow                       // minor indicators; be a little careful
	verdictSuspicious                // multiple red flags; likely a scam
	verdictDangerous                 // near-certain phishing / drainer scam
)

func (v verdict) label() string {
	switch v {
	case verdictDangerous:
		return "DANGEROUS"
	case verdictSuspicious:
		return "SUSPICIOUS"
	case verdictLow:
		return "LOW RISK"
	default:
		return "SAFE"
	}
}

// signal is one detected indicator with the risk weight it contributes.
type signal struct {
	code   string
	weight int
	detail string
}

// input is everything assess() needs, already normalized to lowercase. Keeping
// it a plain struct makes the whole detector pure and unit-testable with no
// network or engine dependencies.
type input struct {
	host        string // lowercase hostname, no port
	domain      string // registrable domain (eTLD+1)
	scheme      string // "http" | "https"
	hasUserinfo bool   // URL contained user:pass@ (a classic deception)
	path        string // lowercase path + raw query
	title       string // lowercase <title> text (may be "")
	body        string // lowercase page body (may be "")
}

// assessment is the full result: a 0–100 risk score, a verdict, the impersonated
// brand (if any), and the individual signals that explain the score.
type assessment struct {
	score       int
	verdict     verdict
	brand       string // impersonated brand, if impersonation detected
	legit       bool   // domain is a recognized official brand domain
	seedHarvest bool
	passwordForm bool
	signals     []signal
}

// assess runs the full heuristic pipeline over a single target. It is the heart
// of the module and is deliberately corroboration-aware: soft signals only
// escalate to "dangerous" when they reinforce each other, which is what keeps
// false positives on legitimate sites low.
func assess(in input) assessment {
	a := assessment{}
	add := func(code string, weight int, detail string) {
		a.signals = append(a.signals, signal{code, weight, detail})
	}

	sld := secondLevel(in.domain)
	a.legit = isOfficialDomain(in.domain)
	a.passwordForm = mentionsAny(in.body, `type="password"`, "type='password'", "type=password")
	a.seedHarvest = mentionsAny(in.body, seedPhraseMarkers...) || mentionsAny(in.title, seedPhraseMarkers...)

	// --- 1. Brand impersonation (skipped for recognized official domains) ---
	var impWeight int
	if !a.legit {
		if b, kind, w := detectImpersonation(in.host, in.domain, sld); w > 0 {
			a.brand = b
			impWeight = w
			add("impersonation:"+kind, w, "The domain imitates "+b+" but is not an official "+b+" domain.")
		}
	}

	// --- 2. Wallet / seed-phrase harvesting (unambiguous when present) ---
	if a.seedHarvest {
		add("seed-harvest", 55, "The page asks for a wallet recovery/seed phrase or private key — no legitimate service ever does this.")
	}
	// Drainer "connect wallet" flows are normal on real DeFi, so they only count
	// when the site is already impersonating a brand or on an abuse TLD.
	if mentionsAny(in.body, walletDrainerMarkers...) && (impWeight > 0 || isAbuseTLD(in.domain)) {
		add("wallet-drainer", 22, "A 'connect/validate wallet' flow combined with other red flags is a common wallet-drainer pattern.")
	}
	// A credential form on a lookalike domain turns a suspicious domain into an
	// active credential-phishing page.
	if a.passwordForm && impWeight > 0 {
		add("credential-form", 18, "The page collects a password while impersonating "+a.brand+".")
	}

	// --- 3. Brand mentioned in content but domain doesn't match ---
	if !a.legit {
		if b := brandInContent(in.title + " " + in.body); b != "" && b != a.brand {
			add("brand-content", 20, "The page presents itself as "+b+", but the domain is not owned by "+b+".")
		}
	}

	// --- 4. Deceptive URL / hostname structure ---
	for _, s := range detectURLDeception(in) {
		a.signals = append(a.signals, s)
	}

	// --- 5. Scam-genre keyword clusters (supporting context) ---
	hay := strings.Join([]string{in.host, in.path, in.title, in.body}, " ")
	clusterWeight := 0
	for _, c := range scamKeywordClusters {
		if matchesCluster(hay, c.all, c.any) && clusterWeight < 24 {
			clusterWeight += 8
			add("scam:"+c.name, 8, "Content matches a known "+c.label+".")
		}
	}

	// --- Aggregate ---
	for _, s := range a.signals {
		a.score += s.weight
	}
	if a.score > 100 {
		a.score = 100
	}
	a.verdict = scoreToVerdict(a.score)

	// Hard overrides: some signals are conclusive on their own.
	if a.seedHarvest {
		a.verdict = verdictDangerous
	}
	if impWeight >= 35 && a.passwordForm {
		a.verdict = verdictDangerous
	}
	return a
}

// detectImpersonation returns the best (highest-weight) brand-impersonation
// match for a host, or weight 0 if none. kind describes how it matched, for the
// human-readable finding.
func detectImpersonation(host, domain, sld string) (brandName, kind string, weight int) {
	normSld := deleet(sld)
	for _, b := range brands {
		for _, od := range b.domains {
			// Subdomain deception: the real brand domain embedded inside a
			// different registrable domain (paypal.com.secure-login.xyz).
			if containsLabelSeq(host, od) && domain != od {
				return b.name, "subdomain", 46
			}
		}
		for _, tok := range b.tokens {
			// Combosquat: brand token at a boundary, fused with an affix word,
			// or standing alone as a DNS label on a non-brand domain.
			combo := (len(tok) >= 4 && (boundaryContains(sld, tok) || affixConcat(sld, tok))) ||
				labelPresent(host, tok, domain)
			if combo {
				weight, brandName, kind = keepMax(weight, 35, brandName, kind, b.name, "combosquat")
			}
			// Homoglyph / leetspeak: paypa1, g00gle, b1nance.
			if len(tok) >= 4 && normSld != sld && (normSld == tok || levenshtein(normSld, tok) <= 1) {
				weight, brandName, kind = keepMax(weight, 42, brandName, kind, b.name, "homoglyph")
			}
			// Typosquat: 1–2 character edits from the real brand.
			if len(tok) >= 5 && sld != tok {
				switch levenshtein(sld, tok) {
				case 1:
					weight, brandName, kind = keepMax(weight, 35, brandName, kind, b.name, "typosquat")
				case 2:
					if len(sld) >= 6 {
						weight, brandName, kind = keepMax(weight, 22, brandName, kind, b.name, "typosquat")
					}
				}
			}
		}
	}
	return brandName, kind, weight
}

// detectURLDeception returns structural red flags in the hostname / URL itself.
func detectURLDeception(in input) []signal {
	var out []signal
	add := func(code string, w int, d string) { out = append(out, signal{code, w, d}) }

	labels := strings.Split(in.host, ".")
	if net.ParseIP(in.host) != nil {
		if in.path != "" || in.body != "" {
			add("ip-host", 20, "The site is served from a bare IP address instead of a domain name — unusual for a legitimate service.")
		} else {
			add("ip-host", 10, "The site is served from a bare IP address instead of a domain name.")
		}
	}
	if in.hasUserinfo {
		add("userinfo", 16, "The link embeds credentials before an '@', a classic trick to disguise the real destination.")
	}
	if hasPunycode(in.host) {
		add("punycode", 18, "The domain uses punycode (xn--), which can hide look-alike Unicode characters (homograph attack).")
	}
	if len(labels) >= 5 {
		add("deep-subdomain", 12, "The hostname has an unusually deep subdomain chain, often used to bury a fake brand name.")
	} else if len(labels) == 4 {
		add("deep-subdomain", 6, "The hostname has several subdomain levels.")
	}
	for _, l := range labels {
		if strings.Count(l, "-") >= 3 {
			add("hyphenated", 8, "A hostname label packed with hyphens is a common scam-domain trait.")
			break
		}
	}
	if isAbuseTLD(in.domain) {
		add("abuse-tld", 10, "The domain uses a top-level domain frequently abused for free throwaway scam sites.")
	}
	if in.scheme == "http" && in.passwordFormHint() {
		add("http-login", 15, "The page collects credentials over plain HTTP with no encryption.")
	}
	for _, kw := range []string{"webscr", "cmd=_login", "signin", "secure-login", "account-verify", "wp-login", "confirm-account"} {
		if strings.Contains(in.path, kw) {
			add("phishy-path", 8, "The URL path mimics a login/verification endpoint.")
			break
		}
	}
	return out
}

// passwordFormHint lets detectURLDeception react to a credential form without
// re-parsing the body.
func (in input) passwordFormHint() bool {
	return mentionsAny(in.body, `type="password"`, "type='password'", "type=password")
}

func scoreToVerdict(score int) verdict {
	switch {
	case score >= 65:
		return verdictDangerous
	case score >= 35:
		return verdictSuspicious
	case score >= 15:
		return verdictLow
	default:
		return verdictClean
	}
}

// --- small pure helpers ------------------------------------------------------

// keepMax returns the higher-weight of the current and candidate match, updating
// the brand/kind to whichever wins.
func keepMax(cur, cand int, curBrand, curKind, candBrand, candKind string) (int, string, string) {
	if cand > cur {
		return cand, candBrand, candKind
	}
	return cur, curBrand, curKind
}

func secondLevel(domain string) string {
	if i := strings.IndexByte(domain, '.'); i > 0 {
		return domain[:i]
	}
	return domain
}

func isOfficialDomain(domain string) bool {
	for _, b := range brands {
		for _, od := range b.domains {
			if domain == od {
				return true
			}
		}
	}
	return false
}

func isAbuseTLD(domain string) bool {
	i := strings.LastIndexByte(domain, '.')
	if i < 0 {
		return false
	}
	return abuseTLDs[domain[i+1:]]
}

func hasPunycode(host string) bool {
	for _, l := range strings.Split(host, ".") {
		if strings.HasPrefix(l, "xn--") {
			return true
		}
	}
	return false
}

func mentionsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func brandInContent(text string) string {
	for _, b := range brands {
		for _, tok := range b.tokens {
			if len(tok) >= 5 && strings.Contains(text, tok) {
				return b.name
			}
		}
	}
	return ""
}

func matchesCluster(hay string, all, any []string) bool {
	for _, a := range all {
		if !strings.Contains(hay, a) {
			return false
		}
	}
	if len(any) == 0 {
		return len(all) > 0
	}
	for _, a := range any {
		if strings.Contains(hay, a) {
			return true
		}
	}
	return false
}

// boundaryContains reports whether tok appears inside label delimited by
// non-letter characters (start/end, hyphen, digit) — so "paypal-login" matches
// but "appleseed" does not match "apple".
func boundaryContains(label, tok string) bool {
	from := 0
	for {
		idx := strings.Index(label[from:], tok)
		if idx < 0 {
			return false
		}
		idx += from
		beforeOK := idx == 0 || !isLetter(label[idx-1])
		end := idx + len(tok)
		afterOK := end == len(label) || !isLetter(label[end])
		if beforeOK && afterOK {
			return true
		}
		from = idx + 1
	}
}

// affixConcat reports whether label is exactly a brand token fused to a phishy
// affix, e.g. "verifypaypal" or "applesupport".
func affixConcat(label, tok string) bool {
	for _, af := range affixes {
		if label == tok+af || label == af+tok {
			return true
		}
	}
	return false
}

// labelPresent reports whether tok appears as a full DNS label anywhere in host
// while the registrable domain is not that brand — e.g. "paypal.evil.xyz".
func labelPresent(host, tok, domain string) bool {
	if secondLevel(domain) == tok {
		return false // the brand token IS this domain's own label; handled elsewhere
	}
	for _, l := range strings.Split(host, ".") {
		if l == tok {
			return true
		}
	}
	return false
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// deleet normalizes common homoglyph / leetspeak substitutions back to letters
// so "paypa1", "g00gle" and "b1nance" collapse toward the real brand name.
func deleet(s string) string {
	repl := map[byte]byte{
		'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
		'7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a',
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if r, ok := repl[s[i]]; ok {
			out = append(out, r)
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// containsLabelSeq reports whether od (a dotted domain) appears as a contiguous
// run of labels inside host that is NOT the trailing run — i.e. a genuine
// subdomain-deception, not a legitimate subdomain of od.
func containsLabelSeq(host, od string) bool {
	hs := strings.Split(host, ".")
	os := strings.Split(od, ".")
	if len(os) == 0 || len(os) >= len(hs) {
		return false
	}
	for i := 0; i+len(os) <= len(hs); i++ {
		if equalSlice(hs[i:i+len(os)], os) && i+len(os) != len(hs) {
			return true
		}
	}
	return false
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// levenshtein is the classic edit distance, used for typosquat detection.
func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
