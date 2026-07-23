package phishing

import (
	"net"
	"regexp"
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
	pageFailed  bool   // primary HTTP(S) fetch failed (reset, timeout, refused)
	pageStatus  int    // HTTP status when fetch succeeded (0 if failed)
	hostingHint string // lowercase ASN/org evidence from intel (optional)
	ageDays     int    // domain age in days; -1 unknown (mirrors netResult)
}

// assessment is the full result: a 0–100 risk score, a verdict, the impersonated
// brand (if any), and the individual signals that explain the score.
type assessment struct {
	score        int
	verdict      verdict
	brand        string // impersonated brand, if impersonation detected
	legit        bool   // domain is a recognized official brand domain
	seedHarvest  bool
	passwordForm bool
	signals      []signal
}

// passwordInputRe matches a real HTML password field — not CSS selectors like
// input[type=password] that legitimate themes ship in stylesheets (watoto.com).
var passwordInputRe = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password\b`)

// assess runs the full heuristic pipeline over a single target. It is the heart
// of the module and is deliberately corroboration-aware: soft signals only
// escalate to "dangerous" when they reinforce each other, which is what keeps
// false positives on legitimate sites low.
func assess(in input, extra ...signal) assessment {
	a := assessment{}
	add := func(code string, weight int, detail string) {
		a.signals = append(a.signals, signal{code, weight, detail})
	}

	sld := secondLevel(in.domain)
	a.legit = isOfficialDomain(in.domain)
	a.passwordForm = passwordInputRe.MatchString(in.body)
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
	// when the site is already impersonating a brand or on an abuse TLD / lexical scam.
	lexicalHit := false
	for _, s := range detectLexicalDomain(in.domain, sld) {
		a.signals = append(a.signals, s)
		lexicalHit = true
	}
	if mentionsAny(in.body, walletDrainerMarkers...) && (impWeight > 0 || isAbuseTLD(in.domain) || lexicalHit) {
		add("wallet-drainer", 22, "A 'connect/validate wallet' flow combined with other red flags is a common wallet-drainer pattern.")
	}
	// A credential form on a lookalike domain turns a suspicious domain into an
	// active credential-phishing page.
	if a.passwordForm && impWeight > 0 {
		add("credential-form", 18, "The page collects a password while impersonating "+a.brand+".")
	}

	// --- 3. Brand mentioned in content but domain doesn't match ---
	// Uses presentation-aware matching so social share links and CSS (applewebkit,
	// fonts.googleapis.com) never falsely flag a charity or blog as phishing.
	if !a.legit {
		if b := brandInContent(in.title, in.body); b != "" && b != a.brand {
			add("brand-content", 20, "The page presents itself as "+b+", but the domain is not owned by "+b+".")
		}
	}

	// --- 4. Deceptive URL / hostname structure ---
	for _, s := range detectURLDeception(in) {
		a.signals = append(a.signals, s)
	}

	// --- 5. Scam-genre keyword clusters (supporting context) ---
	hay := strings.Join([]string{in.host, in.path, in.title, stripTags(in.body)}, " ")
	clusterWeight := 0
	for _, c := range scamKeywordClusters {
		hits := clusterHits(hay, c)
		if hits > 0 && clusterWeight < 32 {
			w := c.weight
			if w <= 0 {
				w = 10
			}
			// Multiple matching phrases inside one playbook is a much stronger signal.
			if hits >= 3 {
				w += 10
			} else if hits >= 2 {
				w += 6
			}
			if clusterWeight+w > 32 {
				w = 32 - clusterWeight
			}
			clusterWeight += w
			add("scam:"+c.name, w, "Content matches a known "+c.label+".")
		}
	}

	// --- 6. Page unreachable (common for sinkholed / blocked / park-and-phish) ---
	if in.pageFailed {
		add("unreachable", 10, "The site could not be loaded over HTTPS — scammers often hide or take down kits after campaigns.")
	}

	// --- 7. High-risk hosting fingerprint (soft; corroborates youth / lexical) ---
	if hint := strings.ToLower(in.hostingHint); hint != "" {
		for _, h := range highRiskHosting {
			if strings.Contains(hint, h) {
				add("hosting-risk", 8, "The site is hosted on infrastructure frequently used by disposable scam sites.")
				break
			}
		}
	}

	// --- Network-derived reputation signals (domain age, blocklists) ---
	a.signals = append(a.signals, extra...)

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

	has := func(code string) bool {
		for _, s := range a.signals {
			if s.code == code || strings.HasPrefix(s.code, code) {
				return true
			}
		}
		return false
	}
	hasBlocklist := has("blocklist")
	hasNew := has("domain-new")
	hasYoung := has("domain-young") || hasNew
	hasLexical := has("lexical")
	hasScamContent := has("scam:")
	hasUnreach := has("unreachable")
	hasHosting := has("hosting-risk")
	hasAbuseTLD := has("abuse-tld")

	// A conclusive signal is one that, on its own, justifies a scam verdict: an
	// abuse blocklist listing, seed-phrase harvesting, or brand impersonation
	// paired with credential/registration evidence. Everything else — a
	// scam-shaped name, youth, cheap hosting, an abuse TLD, a keyword cluster —
	// is CIRCUMSTANTIAL and must corroborate before it means anything. This is
	// the core false-positive defense: a legitimate young AI/fintech company on
	// a .io domain trips at most one circumstantial signal and stays SAFE/LOW.
	if hasBlocklist {
		a.verdict = verdictDangerous
	}
	if impWeight > 0 && hasNew && a.verdict < verdictDangerous {
		a.verdict = verdictDangerous // fresh domain actively impersonating a brand
	}

	// Count independent circumstantial corroborators.
	corroborators := 0
	for _, c := range []bool{hasScamContent, hasUnreach, hasHosting, hasAbuseTLD, hasYoung} {
		if c {
			corroborators++
		}
	}

	// Page content matching a known scam playbook is the strongest circumstantial
	// signal — when it co-occurs with a scam-shaped name or youth, it's a scam.
	if hasScamContent && (hasLexical || hasYoung || hasAbuseTLD) && a.verdict < verdictSuspicious {
		a.verdict = verdictSuspicious
	}

	// A scam-shaped name only escalates with at least two OTHER corroborators
	// (e.g. young + unreachable, or abuse-TLD + scam content). Name + one weak
	// signal stays LOW.
	if hasLexical && corroborators >= 2 && a.verdict < verdictSuspicious {
		a.verdict = verdictSuspicious
		if a.score < 34 {
			a.score = 34
		}
	}

	// Full disposable-kit fingerprint: scam-shaped name + fresh domain + dead
	// origin + abuse-tolerant hosting. This is an unambiguous throwaway scam.
	if hasLexical && hasNew && hasUnreach && hasHosting && a.verdict < verdictDangerous {
		a.verdict = verdictDangerous
		if a.score < 65 {
			a.score = 65
		}
	}

	// Established-domain trust: multi-year domains with only soft signals stay SAFE.
	// This is the antidote to keyword/CSS noise on legitimate charities and orgs.
	if in.ageDays >= 5*365 && !hasBlocklist && !a.seedHarvest && impWeight == 0 {
		softOnly := true
		for _, s := range a.signals {
			if s.weight >= 18 && !strings.HasPrefix(s.code, "scam:") {
				// brand-content / strong URL deception still matter even on aged domains
				if s.code == "brand-content" || s.code == "userinfo" || s.code == "punycode" || s.code == "ip-host" {
					softOnly = false
					break
				}
				if strings.HasPrefix(s.code, "impersonation:") {
					softOnly = false
					break
				}
			}
			if s.code == "seed-harvest" || s.code == "credential-form" {
				softOnly = false
				break
			}
		}
		if softOnly && a.verdict <= verdictLow {
			a.verdict = verdictClean
			a.score = 0
			// Keep informative signals out of the score for established clean domains.
			a.signals = nil
		}
	}

	return a
}

// detectLexicalDomain scores throwaway investment / AI / crypto scam domain names
// that never impersonate a famous brand (e.g. future-aihub.com, earn-crypto-bot.xyz).
func detectLexicalDomain(domain, sld string) []signal {
	var out []signal
	if sld == "" {
		return out
	}
	// Normalize hyphens for token search while keeping the original for evidence.
	flat := strings.ReplaceAll(sld, "-", "")

	for _, tok := range scamDomainTokens {
		tokFlat := strings.ReplaceAll(tok, "-", "")
		if len(tokFlat) < 5 {
			continue
		}
		if flat == tokFlat || strings.Contains(flat, tokFlat) || strings.Contains(sld, tok) {
			out = append(out, signal{
				// Weak on its own (below the LOW threshold): a scam-shaped *name*
				// is only a prior. Real legitimate businesses use names like
				// "aitrading" or "smartinvest", so this must be corroborated by
				// content, youth+infra, or reputation before it means anything.
				code:   "lexical-scam-name",
				weight: 14,
				detail: "The domain name uses wording common to fake investment, AI-trading, and crypto-scam sites (weak on its own).",
			})
			return out
		}
	}

	// Corroborated weak parts: a scam-combo requires an explicit high-intent
	// money/urgency word (earn, profit, bonus, airdrop, giveaway, doubler, …)
	// PLUS a commercial word. Two generic fintech words ("future"+"finance",
	// "smart"+"capital") are NOT enough — that pattern is overwhelmingly legit.
	parts := strings.FieldsFunc(sld, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	hits := findScamPartHits(flat, parts)
	if len(hits) >= 2 && hasHighIntentPart(hits) {
		w := 12
		if len(hits) >= 3 {
			w = 16
		}
		out = append(out, signal{
			code:   "lexical-scam-combo",
			weight: w,
			detail: "The domain fuses a get-rich / claim / giveaway word with investment or crypto terms, a throwaway-scam naming style.",
		})
	}

	// Heavy hyphenation on a commercial SLD is a mild supporting signal, and only
	// when a high-intent word is present.
	if strings.Count(sld, "-") >= 2 && hasHighIntentPart(hits) {
		out = append(out, signal{
			code:   "lexical-hyphenated",
			weight: 6,
			detail: "The domain packs multiple hyphenated get-rich marketing words — a common disposable-scam naming style.",
		})
	}
	return out
}

// highIntentParts are the words that signal actual scam intent, as opposed to
// generic commercial vocabulary that legitimate fintech/AI companies also use.
// Every entry must also exist in scamDomainParts so findScamPartHits can surface
// it. Generic words (invest, trade, finance, capital, ai, hub, future, smart) are
// deliberately excluded — they are overwhelmingly legitimate.
var highIntentParts = map[string]bool{
	"earn": true, "profit": true, "bonus": true, "reward": true,
	"airdrop": true, "claim": true, "rich": true, "wealth": true, "yield": true,
}

// hasHighIntentPart reports whether the detected SLD parts include at least one
// unambiguous scam-intent word.
func hasHighIntentPart(hits map[string]bool) bool {
	for tok := range hits {
		if highIntentParts[tok] {
			return true
		}
	}
	return false
}

// findScamPartHits returns distinct scamDomainParts found in a flattened SLD.
// Longer tokens are preferred so "bitcoin" wins over "bit"/"coin" fragments.
// Short tokens (≤3 chars) only count at a letter boundary to avoid "hub" in "github".
func findScamPartHits(flat string, hyphenParts []string) map[string]bool {
	hits := map[string]bool{}
	for _, p := range hyphenParts {
		for _, tok := range scamDomainParts {
			if p == tok {
				hits[tok] = true
			}
		}
	}
	// Longest-first scan for concatenated forms (futureaihub → future, ai, hub).
	parts := append([]string(nil), scamDomainParts...)
	for i := 0; i < len(parts); i++ {
		for j := i + 1; j < len(parts); j++ {
			if len(parts[j]) > len(parts[i]) {
				parts[i], parts[j] = parts[j], parts[i]
			}
		}
	}
	remaining := flat
	for _, tok := range parts {
		if hits[tok] {
			continue
		}
		if len(tok) <= 3 {
			if boundaryContains(flat, tok) || hasString(hyphenParts, tok) {
				hits[tok] = true
			}
			continue
		}
		if strings.Contains(remaining, tok) || strings.Contains(flat, tok) {
			hits[tok] = true
		}
	}
	return hits
}

func hasString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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
			switch {
			case len(tok) >= 4 && sld == tok:
				// The exact brand word as the whole SLD on a non-official TLD
				// (e.g. tradingview.io, paypal.co). This is frequently a
				// legitimate alternate/regional site, so it is weaker than a
				// combosquat and needs corroboration (abuse TLD, youth) to matter.
				weight, brandName, kind = keepMax(weight, 22, brandName, kind, b.name, "alt-tld")
			case len(tok) >= 4 && (boundaryContains(sld, tok) || affixConcat(sld, tok)):
				// Brand token fused with other words: paypal-secure, verifyapple.
				weight, brandName, kind = keepMax(weight, 35, brandName, kind, b.name, "combosquat")
			case labelPresent(host, tok, domain):
				// Brand word as a full DNS label on a different registrable domain.
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
	if in.scheme == "http" && passwordInputRe.MatchString(in.body) {
		add("http-login", 15, "The page collects credentials over plain HTTP with no encryption.")
	}
	for _, kw := range []string{"webscr", "cmd=_login", "signin", "secure-login", "account-verify", "wp-login", "confirm-account", "wallet-connect", "claim-airdrop"} {
		if strings.Contains(in.path, kw) {
			add("phishy-path", 8, "The URL path mimics a login/verification endpoint.")
			break
		}
	}
	return out
}

func scoreToVerdict(score int) verdict {
	switch {
	case score >= 60:
		return verdictDangerous
	case score >= 32:
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

// brandInContent looks for a brand being *presented as the site itself* — in the
// title or via login/welcome copy — not merely linked as a social profile or
// embedded in third-party asset URLs (fonts.googleapis.com, applewebkit, etc.).
func brandInContent(title, body string) string {
	title = strings.ToLower(title)
	body = strings.ToLower(body)
	// Cap body work: full pages with huge CSS waste cycles and raise FP surface.
	if len(body) > 80_000 {
		body = body[:80_000]
	}
	visible := stripTags(body)
	if len(visible) > 20_000 {
		visible = visible[:20_000]
	}

	for _, b := range brands {
		for _, tok := range b.tokens {
			if len(tok) < 5 {
				continue
			}
			if wordContains(title, tok) {
				return b.name
			}
			// Presentation phrases — the page claims to BE the brand.
			for _, pat := range []string{
				"sign in to " + tok, "log in to " + tok, "login to " + tok,
				"sign in with " + tok, "log in with " + tok,
				"welcome to " + tok, "welcome to your " + tok,
				"official " + tok, tok + " account", tok + " security",
				tok + " support", tok + " help center", tok + " verification",
				"verify your " + tok, "update your " + tok,
				tok + " wallet", "connect " + tok,
			} {
				if strings.Contains(visible, pat) || strings.Contains(body, pat) {
					return b.name
				}
			}
		}
	}
	return ""
}

// wordContains reports whether tok appears as a whole word (letter-delimited).
func wordContains(text, tok string) bool {
	from := 0
	for {
		idx := strings.Index(text[from:], tok)
		if idx < 0 {
			return false
		}
		idx += from
		beforeOK := idx == 0 || !isLetter(text[idx-1])
		end := idx + len(tok)
		afterOK := end == len(text) || !isLetter(text[end])
		if beforeOK && afterOK {
			return true
		}
		from = idx + 1
	}
}

// stripTags removes script/style blocks and HTML tags so keyword scans do not
// match inside CSS/JS identifiers (e.g. type=password selectors, applewebkit).
func stripTags(s string) string {
	s = scriptBlockRe.ReplaceAllString(s, " ")
	s = styleBlockRe.ReplaceAllString(s, " ")
	var b strings.Builder
	b.Grow(len(s) / 2)
	inTag := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '<':
			inTag = true
		case c == '>':
			inTag = false
			b.WriteByte(' ')
		case !inTag:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	styleBlockRe  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style>`)
)

// clusterHits returns how many playbook phrases matched (0 => no match).
func clusterHits(hay string, c keywordCluster) int {
	for _, a := range c.all {
		if !strings.Contains(hay, a) {
			return 0
		}
	}
	if len(c.any) == 0 {
		if len(c.all) > 0 {
			return len(c.all)
		}
		return 0
	}
	need := c.minAny
	if need <= 0 {
		if len(c.all) > 0 {
			need = 1
		} else {
			need = 2
		}
	}
	hits := 0
	for _, a := range c.any {
		if strings.Contains(hay, a) {
			hits++
		}
	}
	if hits < need {
		return 0
	}
	// Count required "all" phrases toward total strength.
	return hits + len(c.all)
}

func matchesCluster(hay string, c keywordCluster) bool {
	return clusterHits(hay, c) > 0
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
