// Package verify implements domain-ownership verification. Active-tier scan
// modules are intrusive enough that we only run them against targets the caller
// has proven they control — by publishing a DNS TXT token. The token is a
// deterministic HMAC of the domain, so it can be issued and checked without any
// server-side state.
package verify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// RecordName is the DNS label owners publish the token under (also checked at
// the apex).
const RecordName = "bastionscan-verify"

// Token returns the deterministic verification token for a domain.
func Token(secret, domain string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.ToLower(strings.TrimSuffix(domain, "."))))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// Record is the full TXT value an owner publishes, e.g.
// "bastionscan-verify=abc123…".
func Record(secret, domain string) string {
	return RecordName + "=" + Token(secret, domain)
}

// Verify reports whether the expected token is published in DNS for the domain.
// It checks TXT at both the apex and _bastionscan.<domain>, resolved over DoH.
func Verify(ctx context.Context, env *scan.Env, secret, domain string) bool {
	token := Token(secret, domain)
	full := RecordName + "=" + token
	for _, name := range []string{domain, "_" + RecordName + "." + domain, "_bastionscan." + domain} {
		for _, rec := range dohTXT(ctx, env, name) {
			r := strings.TrimSpace(rec)
			if strings.EqualFold(r, full) || strings.EqualFold(r, token) {
				return true
			}
		}
	}
	return false
}

func dohTXT(ctx context.Context, env *scan.Env, name string) []string {
	endpoint := "https://dns.google/resolve?type=TXT&name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", env.UserAgent)
	resp, err := env.HTTP.Do(req)
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
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.Unmarshal(body, &dr) != nil {
		return nil
	}
	out := make([]string, 0, len(dr.Answer))
	for _, a := range dr.Answer {
		out = append(out, strings.Trim(a.Data, "\""))
	}
	return out
}
