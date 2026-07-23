package phishing

import "testing"

// These regression tests lock in the false-positive fixes: legitimate sites —
// including AI/fintech/crypto-adjacent names that merely *sound* commercial —
// must never be flagged SUSPICIOUS or DANGEROUS from their name alone, while
// genuine scams (corroborated by content, reputation, or infrastructure) still
// escalate. A scam-shaped name is treated as a weak prior, not a verdict.

func TestFalsePositiveGuards(t *testing.T) {
	legit := []struct{ host, domain string }{
		{"smartinvest.io", "smartinvest.io"},
		{"aitrading.com", "aitrading.com"},
		{"futurefinance.com", "futurefinance.com"},
		{"mystore.shop", "mystore.shop"},
		{"acmehq.online", "acmehq.online"},
		{"jane-blog.info", "jane-blog.info"},
		{"devtools.pro", "devtools.pro"},
		{"coindesk.com", "coindesk.com"},
		{"investopedia.com", "investopedia.com"},
		{"wealthfront.com", "wealthfront.com"},
		{"capitalone.com", "capitalone.com"},
		{"aihub.dev", "aihub.dev"},
		{"tokenmetrics.com", "tokenmetrics.com"},
		{"smartcapital.africa", "smartcapital.africa"},
		{"earn-cashback.top", "earn-cashback.top"}, // legit deals site on a cheap TLD
	}
	for _, s := range legit {
		a := assess(mkInput(s.host, s.domain))
		if a.verdict >= verdictSuspicious {
			t.Errorf("FALSE POSITIVE: %s => %s (score %d) signals=%+v",
				s.domain, a.verdict.label(), a.score, a.signals)
		}
	}
}

func TestTruePositivesStillCaught(t *testing.T) {
	// Domain-only impersonation still fires.
	strong := []struct {
		name       string
		in         input
		extra      []signal
		wantAtLeast verdict
	}{
		{
			name:        "combosquat brand+affix",
			in:          mkInput("paypal-login.com", "paypal-login.com"),
			wantAtLeast: verdictSuspicious,
		},
		{
			name:        "homoglyph brand",
			in:          mkInput("paypa1.com", "paypa1.com"),
			wantAtLeast: verdictSuspicious,
		},
		{
			name: "seed-phrase harvesting is always dangerous",
			in: func() input {
				i := mkInput("wallet-restore.io", "wallet-restore.io")
				i.body = "please enter your 12 word recovery phrase to restore your wallet"
				return i
			}(),
			wantAtLeast: verdictDangerous,
		},
		{
			name:        "fresh domain impersonating a brand => dangerous",
			in:          mkInput("paypal-verify.info", "paypal-verify.info"),
			extra:       []signal{{"domain-new", 30, "registered this week"}},
			wantAtLeast: verdictDangerous,
		},
		{
			name:        "blocklisted domain => dangerous",
			in:          mkInput("some-shop.io", "some-shop.io"),
			extra:       []signal{{"blocklist", 40, "listed"}},
			wantAtLeast: verdictDangerous,
		},
		{
			name: "lexical scam name + young + abuse TLD + unreachable => escalates",
			in: func() input {
				i := mkInput("earn-crypto-bonus.tk", "earn-crypto-bonus.tk")
				i.pageFailed = true
				return i
			}(),
			extra:       []signal{{"domain-young", 12, "young"}},
			wantAtLeast: verdictSuspicious,
		},
	}
	for _, tt := range strong {
		t.Run(tt.name, func(t *testing.T) {
			a := assess(tt.in, tt.extra...)
			if a.verdict < tt.wantAtLeast {
				t.Errorf("MISSED: %s => %s (score %d), want >= %s\nsignals=%+v",
					tt.name, a.verdict.label(), a.score, tt.wantAtLeast.label(), a.signals)
			}
		})
	}
}
