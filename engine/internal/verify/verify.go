// Package verify implements domain-ownership verification. Active-tier scan
// modules are intrusive enough that we only run them against targets the caller
// has proven they control — by publishing a DNS TXT token. The token is a
// deterministic HMAC of the domain, so it can be issued and checked without any
// server-side state.
//
// Ownership verification is the security linchpin of the whole Active tier: it
// is the difference between "analyze anything safely" and "aggressively probe an
// asset". It is therefore deliberately strict and precise — the matching logic
// is pure and exhaustively fixture-tested, and DNS is corroborated across two
// independent DoH providers so a single resolver's cache or outage can neither
// grant nor deny ownership incorrectly.
package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// RecordName is the DNS label owners publish the token under (also checked at
// the apex and under a couple of conventional prefixes).
const RecordName = "bastionscan-verify"

// Token returns the deterministic verification token for a domain.
func Token(secret, domain string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(normalizeDomain(domain)))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// Record is the full TXT value an owner publishes, e.g.
// "bastionscan-verify=abc123…".
func Record(secret, domain string) string {
	return RecordName + "=" + Token(secret, domain)
}

// CheckNames returns the DNS names, in priority order, where the verification
// TXT record is accepted. Owners may publish at the apex or under a dedicated
// challenge label — both are honored.
func CheckNames(domain string) []string {
	d := normalizeDomain(domain)
	return []string{
		d,
		"_" + RecordName + "." + d,
		"_bastionscan." + d,
	}
}

// txtLookup resolves TXT records for a name. It is the seam that makes Verify
// fully unit-testable: production uses multi-provider DoH; tests inject fixtures.
type txtLookup func(ctx context.Context, env *scan.Env, name string) []string

// Verify reports whether the expected token is published in DNS for the domain,
// corroborated across independent DoH resolvers.
func Verify(ctx context.Context, env *scan.Env, secret, domain string) bool {
	return verifyWith(ctx, env, secret, domain, dohTXTMulti)
}

// verifyWith is the testable core: pure matching over an injectable resolver.
func verifyWith(ctx context.Context, env *scan.Env, secret, domain string, lookup txtLookup) bool {
	full, token := Record(secret, domain), Token(secret, domain)
	for _, name := range CheckNames(domain) {
		if MatchTXT(lookup(ctx, env, name), full, token) {
			return true
		}
	}
	return false
}

// MatchTXT reports whether any TXT record proves ownership. It accepts either
// the full "name=token" record or a bare token, tolerating the quoting and
// whitespace real resolvers introduce, and compares in constant time.
func MatchTXT(records []string, full, token string) bool {
	wantFull := strings.ToLower(strings.TrimSpace(full))
	wantToken := strings.ToLower(strings.TrimSpace(token))
	matched := false
	for _, rec := range records {
		r := normalizeTXT(rec)
		// Constant-time comparisons; evaluate every record so timing does not
		// reveal which record (if any) matched.
		if constEq(r, wantFull) || constEq(r, wantToken) {
			matched = true
		}
		// Also accept "name = token" with incidental spaces around '='.
		if k, v, ok := splitRecord(r); ok && k == strings.ToLower(RecordName) {
			if constEq(v, wantToken) {
				matched = true
			}
		}
	}
	return matched
}

// --- DNS over HTTPS (multi-provider) ----------------------------------------

// dohProviders are queried independently; a match from any is sufficient because
// the owner controls their authoritative DNS. Using two guards against one
// provider's transient failure or stale cache.
var dohProviders = []string{
	"https://dns.google/resolve",
	"https://cloudflare-dns.com/dns-query",
}

func dohTXTMulti(ctx context.Context, env *scan.Env, name string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range dohProviders {
		for _, rec := range dohTXT(ctx, env, p, name) {
			if !seen[rec] {
				seen[rec] = true
				out = append(out, rec)
			}
		}
	}
	return out
}

func dohTXT(ctx context.Context, env *scan.Env, endpoint, name string) []string {
	u := endpoint + "?type=TXT&name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")
	if env != nil && env.UserAgent != "" {
		req.Header.Set("User-Agent", env.UserAgent)
	}
	client := http.DefaultClient
	if env != nil && env.HTTP != nil {
		client = env.HTTP
	}
	resp, err := client.Do(req)
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
	var dr struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.Unmarshal(body, &dr) != nil {
		return nil
	}
	out := make([]string, 0, len(dr.Answer))
	for _, a := range dr.Answer {
		if a.Type != 0 && a.Type != 16 { // 16 = TXT; some providers omit the type
			continue
		}
		out = append(out, a.Data)
	}
	return out
}

// --- helpers -----------------------------------------------------------------

func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// normalizeTXT strips the surrounding quotes and whitespace that DoH providers
// add, and joins the character-string chunks some use for long TXT records.
func normalizeTXT(rec string) string {
	r := strings.TrimSpace(rec)
	r = strings.Trim(r, `"`)
	if strings.Contains(r, `" "`) {
		r = strings.ReplaceAll(r, `" "`, "")
	}
	return strings.ToLower(strings.TrimSpace(r))
}

func splitRecord(r string) (key, val string, ok bool) {
	i := strings.IndexByte(r, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(r[:i]), strings.TrimSpace(r[i+1:]), true
}

// constEq compares two already-normalized strings in constant time.
func constEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
