package phishing

import "testing"

// mkInput builds an input with sensible defaults so each test only sets the
// fields it cares about.
func mkInput(host, domain string) input {
	return input{host: host, domain: domain, scheme: "https", ageDays: -1}
}

func TestAssessVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		in      input
		want    verdict
		brand   string // "" => expect no brand
		wantMin verdict // floor: actual verdict must be >= this
	}{
		// --- Legitimate sites must come back SAFE (false-positive guards) ---
		{name: "official paypal", in: mkInput("www.paypal.com", "paypal.com"), want: verdictClean},
		{name: "official google", in: mkInput("accounts.google.com", "google.com"), want: verdictClean},
		{name: "official binance", in: mkInput("binance.com", "binance.com"), want: verdictClean},
		{name: "unrelated brand github", in: mkInput("github.com", "github.com"), want: verdictClean},
		{name: "appleseed is not apple", in: mkInput("appleseed.com", "appleseed.com"), want: verdictClean},
		{name: "cryptonews is not crypto.com", in: mkInput("cryptonews.com", "cryptonews.com"), want: verdictClean},
		{name: "plain blog", in: mkInput("myfavoriterecipes.co.ke", "myfavoriterecipes.co.ke"), want: verdictClean},

		// --- Brand impersonation ---
		{name: "combosquat paypal-login", in: mkInput("paypal-login.com", "paypal-login.com"), wantMin: verdictSuspicious, brand: "PayPal"},
		{name: "combosquat secure-paypal.xyz", in: mkInput("secure-paypal.xyz", "secure-paypal.xyz"), wantMin: verdictSuspicious, brand: "PayPal"},
		{name: "affix fusion verifyapple", in: mkInput("verifyapple.com", "verifyapple.com"), wantMin: verdictSuspicious, brand: "Apple"},
		{name: "homoglyph paypa1", in: mkInput("paypa1.com", "paypa1.com"), wantMin: verdictSuspicious, brand: "PayPal"},
		{name: "leet g00gle", in: mkInput("g00gle.com", "g00gle.com"), wantMin: verdictSuspicious, brand: "Google"},
		{name: "typosquat binancce", in: mkInput("binancce.com", "binancce.com"), wantMin: verdictSuspicious, brand: "Binance"},
		{name: "subdomain deception", in: mkInput("paypal.com.secure-login.xyz", "secure-login.xyz"), wantMin: verdictSuspicious, brand: "PayPal"},
		{name: "brand label on other domain", in: mkInput("binance.rewards-claim.top", "rewards-claim.top"), wantMin: verdictSuspicious, brand: "Binance"},

		// --- Wallet / seed-phrase harvesting is always DANGEROUS ---
		{
			name: "seed phrase harvesting",
			in: func() input {
				i := mkInput("wallet-restore.xyz", "wallet-restore.xyz")
				i.body = `<h1>enter your 12-word recovery phrase to restore your wallet</h1>`
				return i
			}(),
			want: verdictDangerous,
		},

		// --- Impersonation + credential form => DANGEROUS ---
		{
			name: "fake paypal login form",
			in: func() input {
				i := mkInput("paypal-secure.xyz", "paypal-secure.xyz")
				i.body = `<form><input type="password" name="pw"></form> sign in to paypal`
				return i
			}(),
			want:  verdictDangerous,
			brand: "PayPal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := assess(tt.in)
			if tt.wantMin != verdictClean {
				if a.verdict < tt.wantMin {
					t.Errorf("verdict = %s (score %d), want >= %s\nsignals: %+v",
						a.verdict.label(), a.score, tt.wantMin.label(), a.signals)
				}
			} else if a.verdict != tt.want {
				t.Errorf("verdict = %s (score %d), want %s\nsignals: %+v",
					a.verdict.label(), a.score, tt.want.label(), a.signals)
			}
			if tt.brand != "" && a.brand != tt.brand {
				t.Errorf("brand = %q, want %q", a.brand, tt.brand)
			}
		})
	}
}

// TestWatotoFalsePositive guards the exact bug that flagged a 25-year-old
// charity as LOW RISK because CSS contained "applewebkit" / type=password
// selectors and social meta tags for Facebook/Instagram.
func TestWatotoFalsePositive(t *testing.T) {
	i := mkInput("www.watoto.com", "watoto.com")
	i.ageDays = 26 * 365
	i.title = "caring for women & children in uganda & south sudan - watoto"
	i.body = `
		<html><head>
		<style>
		input[type=email],input[type=password],input[type=tel]{border:1px solid #ccc}
		/* Original: https://fonts.googleapis.com/css?family=Open+Sans */
		/* User Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 */
		</style>
		<meta property="article:publisher" content="https://www.facebook.com/watoto" />
		<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Open+Sans"/>
		</head><body>
		<h1>Watoto — caring for women and children</h1>
		<p>Donate to support our work in Uganda and South Sudan.</p>
		<a href="https://www.instagram.com/watotointl/">Instagram</a>
		</body></html>
	`
	a := assess(i)
	if a.verdict != verdictClean {
		t.Fatalf("watoto.com must be SAFE, got %s (%d) signals=%+v", a.verdict.label(), a.score, a.signals)
	}
	if a.passwordForm {
		t.Error("CSS type=password selector must not count as a password form")
	}
}

// TestFutureAIHubScam is the inverse: a young AI-investment-style domain with
// no brand impersonation, unreachable origin, and abuse-tolerant hosting must
// escalate well above "LOW RISK".
func TestFutureAIHubScam(t *testing.T) {
	i := mkInput("future-aihub.com", "future-aihub.com")
	i.ageDays = 99
	i.pageFailed = true
	i.hostingHint = "ddos-guard.net as57724 ddos-guard ltd rostov"
	young, _ := ageToSignal(99)
	a := assess(i, young)
	if a.verdict < verdictSuspicious {
		t.Fatalf("future-aihub.com must be >= SUSPICIOUS, got %s (%d) signals=%+v",
			a.verdict.label(), a.score, a.signals)
	}
	if !hasSignal(a.signals, "lexical-scam-name") && !hasSignal(a.signals, "lexical-scam-combo") {
		t.Errorf("expected lexical scam signal, got %+v", a.signals)
	}
}

func TestURLDeceptionSignals(t *testing.T) {
	cases := []struct {
		name string
		in   input
		code string
	}{
		{"ip host", input{host: "203.0.113.9", domain: "203.0.113.9", scheme: "http", body: "login here"}, "ip-host"},
		{"userinfo", input{host: "paypal.com", domain: "paypal.com", scheme: "https", hasUserinfo: true}, "userinfo"},
		{"punycode", input{host: "xn--pypal-4ve.com", domain: "xn--pypal-4ve.com", scheme: "https"}, "punycode"},
		{"abuse tld", input{host: "free-money.tk", domain: "free-money.tk", scheme: "https"}, "abuse-tld"},
		{"deep subdomain", input{host: "a.b.c.d.example.com", domain: "example.com", scheme: "https"}, "deep-subdomain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectURLDeception(c.in)
			if !hasSignal(got, c.code) {
				t.Errorf("expected signal %q, got %+v", c.code, got)
			}
		})
	}
}

func TestScamKeywordClusters(t *testing.T) {
	i := mkInput("giveaway-event.top", "giveaway-event.top")
	i.body = "elon musk bitcoin giveaway — double your crypto! send 1 btc get 2 back"
	a := assess(i)
	if a.verdict < verdictSuspicious {
		t.Errorf("crypto giveaway should be at least suspicious, got %s (%d): %+v",
			a.verdict.label(), a.score, a.signals)
	}
}

func TestNoFalsePositiveOnLegitLoginForm(t *testing.T) {
	// A real login page on its own (non-brand) domain with a password field must
	// not be flagged — a password form alone is normal.
	i := mkInput("app.mystartup.io", "mystartup.io")
	i.body = `<form><input type="password"></form>`
	a := assess(i)
	if a.verdict != verdictClean {
		t.Errorf("legit login form flagged: %s (%d) %+v", a.verdict.label(), a.score, a.signals)
	}
	if !a.passwordForm {
		t.Error("real <input type=password> must be detected")
	}
}

func TestConnectWalletNeedsCorroboration(t *testing.T) {
	// "connect wallet" on a legitimate-looking dApp domain must NOT alone trigger.
	i := mkInput("app.somedefi.io", "somedefi.io")
	i.body = "connect wallet to continue"
	a := assess(i)
	if a.verdict >= verdictSuspicious {
		t.Errorf("connect-wallet alone should not be suspicious: %s %+v", a.verdict.label(), a.signals)
	}
	// But combined with impersonation it should escalate.
	i2 := mkInput("metamask-connect.xyz", "metamask-connect.xyz")
	i2.body = "connect wallet to validate"
	a2 := assess(i2)
	if a2.verdict < verdictSuspicious {
		t.Errorf("connect-wallet + impersonation should be suspicious: %s %+v", a2.verdict.label(), a2.signals)
	}
}

func TestLexicalScamNames(t *testing.T) {
	cases := []string{
		"future-aihub.com",
		"crypto-earn-bot.xyz",
		"ai-trading-hub.com",
		"bitcoin-giveaway.top",
	}
	for _, d := range cases {
		t.Run(d, func(t *testing.T) {
			sld := secondLevel(d)
			sigs := detectLexicalDomain(d, sld)
			if len(sigs) == 0 {
				t.Errorf("expected lexical signal for %s", d)
			}
		})
	}
	// github must not look like a scam name.
	if sigs := detectLexicalDomain("github.com", "github"); len(sigs) > 0 {
		t.Errorf("github must not be lexical-scam: %+v", sigs)
	}
}

func TestBrandInContentIgnoresAssets(t *testing.T) {
	title := "caring for women & children - watoto"
	body := `applewebkit fonts.googleapis.com facebook.com/watoto instagram.com/org`
	if b := brandInContent(title, body); b != "" {
		t.Errorf("asset/social noise must not claim brand, got %q", b)
	}
	// Real presentation must still fire.
	if b := brandInContent("paypal login", "please sign in to paypal to continue"); b != "PayPal" {
		t.Errorf("presentation copy should detect PayPal, got %q", b)
	}
}

func hasSignal(sigs []signal, code string) bool {
	for _, s := range sigs {
		if s.code == code {
			return true
		}
	}
	return false
}

// --- pure helper unit tests --------------------------------------------------

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"paypal", "paypal", 0},
		{"binancce", "binance", 1},
		{"paypa1", "paypal", 1},
		{"kraken", "kraked", 1},
		{"", "abc", 3},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestDeleet(t *testing.T) {
	cases := map[string]string{
		"paypa1":    "paypal",
		"g00gle":    "google",
		"micr0s0ft": "microsoft",
		"apple":     "apple",
	}
	for in, want := range cases {
		if got := deleet(in); got != want {
			t.Errorf("deleet(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBoundaryContains(t *testing.T) {
	cases := []struct {
		label, tok string
		want       bool
	}{
		{"paypal-login", "paypal", true},
		{"secure-paypal", "paypal", true},
		{"paypal", "paypal", true},
		{"appleseed", "apple", false},
		{"mypaypalx", "paypal", false},
	}
	for _, c := range cases {
		if got := boundaryContains(c.label, c.tok); got != c.want {
			t.Errorf("boundaryContains(%q,%q) = %v, want %v", c.label, c.tok, got, c.want)
		}
	}
}

func TestContainsLabelSeq(t *testing.T) {
	if !containsLabelSeq("paypal.com.secure-login.xyz", "paypal.com") {
		t.Error("expected subdomain deception match")
	}
	if containsLabelSeq("www.paypal.com", "paypal.com") {
		t.Error("legit subdomain must not be flagged as deception")
	}
	if containsLabelSeq("mypaypal.com", "paypal.com") {
		t.Error("substring that is not a full label run must not match")
	}
}
