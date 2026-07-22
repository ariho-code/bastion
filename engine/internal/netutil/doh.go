package netutil

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DoHEndpoint is the DNS-over-HTTPS JSON resolver used for keyless DNS lookups
// (reputation blocklists, TXT records). Google's resolver speaks the widely
// supported application/dns-json format.
const DoHEndpoint = "https://dns.google/resolve"

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// LookupDoH resolves name/qtype over DNS-over-HTTPS using the supplied
// SSRF-guarded client and returns the raw answer data strings. It never errors:
// any failure (network, non-200, malformed JSON) yields an empty slice, which
// callers treat as "no record" — the safe default for reputation checks.
func LookupDoH(ctx context.Context, client *http.Client, userAgent, name, qtype string) []string {
	endpoint := DoHEndpoint + "?name=" + url.QueryEscape(name) + "&type=" + url.QueryEscape(qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/dns-json")

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
	var dr dohResponse
	if json.Unmarshal(body, &dr) != nil {
		return nil
	}
	out := make([]string, 0, len(dr.Answer))
	for _, a := range dr.Answer {
		out = append(out, strings.Trim(strings.TrimSpace(a.Data), "\""))
	}
	return out
}
