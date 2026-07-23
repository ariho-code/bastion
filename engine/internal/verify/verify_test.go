package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func TestTokenDeterministicAndScoped(t *testing.T) {
	secret := "s3cret"
	a1 := Token(secret, "example.com")
	a2 := Token(secret, "EXAMPLE.COM.") // case + trailing dot normalized
	if a1 != a2 {
		t.Errorf("token should be normalized: %q != %q", a1, a2)
	}
	if len(a1) != 32 {
		t.Errorf("token length = %d, want 32", len(a1))
	}
	if Token(secret, "other.com") == a1 {
		t.Error("different domains must produce different tokens")
	}
	if Token("different", "example.com") == a1 {
		t.Error("different secrets must produce different tokens")
	}
}

func TestRecordFormat(t *testing.T) {
	rec := Record("s", "example.com")
	if !strings.HasPrefix(rec, RecordName+"=") {
		t.Errorf("record %q must start with %q=", rec, RecordName)
	}
}

func TestCheckNames(t *testing.T) {
	names := CheckNames("Example.COM.")
	want := []string{"example.com", "_bastionscan-verify.example.com", "_bastionscan.example.com"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("name[%d] = %q, want %q", i, names[i], want[i])
		}
	}
}

// MatchTXT is the precision core of ownership verification. These fixtures cover
// the record shapes real resolvers return, plus every near-miss that must NOT
// be accepted.
func TestMatchTXT(t *testing.T) {
	const secret, domain = "verify-secret", "acme.io"
	full := Record(secret, domain)  // bastionscan-verify=<token>
	token := Token(secret, domain)  // bare token

	cases := []struct {
		name    string
		records []string
		want    bool
	}{
		{"exact full record", []string{full}, true},
		{"bare token", []string{token}, true},
		{"quoted full record (DoH style)", []string{`"` + full + `"`}, true},
		{"uppercased record", []string{strings.ToUpper(full)}, true},
		{"spaces around equals", []string{RecordName + " = " + token}, true},
		{"among other TXT records", []string{"v=spf1 include:_spf.google.com ~all", full}, true},
		{"chunked long TXT", []string{`"bastionscan-verify=` + token[:16] + `" "` + token[16:] + `"`}, true},
		{"whitespace padding", []string{"  " + full + "  "}, true},

		{"no records", nil, false},
		{"unrelated records only", []string{"v=spf1 ~all", "google-site-verification=abc"}, false},
		{"wrong token", []string{RecordName + "=" + strings.Repeat("0", 32)}, false},
		{"token prefix only (truncated)", []string{token[:16]}, false},
		{"token with extra suffix", []string{token + "deadbeef"}, false},
		{"different label same token", []string{"other-verify=" + token}, false},
		{"empty string", []string{""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchTXT(c.records, full, token); got != c.want {
				t.Errorf("MatchTXT(%q) = %v, want %v", c.records, got, c.want)
			}
		})
	}
}

// TestVerifyWithFixtures drives the full Verify flow through an injected
// resolver, proving name selection + matching work end to end without network.
func TestVerifyWithFixtures(t *testing.T) {
	const secret, domain = "s", "verified-owner.com"

	// Owner published the token only under the challenge label, not the apex.
	byName := map[string][]string{
		"_bastionscan-verify.verified-owner.com": {Record(secret, domain)},
		"verified-owner.com":                     {"v=spf1 ~all"},
	}
	lookup := func(_ context.Context, _ *scan.Env, name string) []string {
		return byName[name]
	}
	if !verifyWith(context.Background(), nil, secret, domain, lookup) {
		t.Error("should verify when the token is published under the challenge label")
	}

	// A domain with no token anywhere must not verify (the critical safety case:
	// an unverified target must never unlock Active scanning).
	empty := func(_ context.Context, _ *scan.Env, _ string) []string { return nil }
	if verifyWith(context.Background(), nil, secret, "attacker-controlled.com", empty) {
		t.Error("must NOT verify a domain with no published token")
	}

	// The wrong secret's token must not verify this domain.
	wrong := func(_ context.Context, _ *scan.Env, name string) []string {
		if name == domain {
			return []string{Record("attacker-secret", domain)}
		}
		return nil
	}
	if verifyWith(context.Background(), nil, secret, domain, wrong) {
		t.Error("a token minted with a different secret must not verify")
	}
}
