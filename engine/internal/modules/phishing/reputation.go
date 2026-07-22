package phishing

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// netResult holds the network-derived reputation of a domain: how old it is
// (a brand-new domain is a top phishing signal) and whether it appears on
// domain blocklists / malware feeds. It also carries the risk signals these
// produce so they can be folded into the lexical assessment.
type netResult struct {
	signals    []signal
	ageDays    int      // -1 when unknown
	regDate    string   // YYYY-MM-DD, "" when unknown
	blocklists []string // reputable lists that flagged the domain
	registrar  string   // registrar name when RDAP provides it
}

// gatherReputation runs RDAP age, multi-blocklist, and URLHaus lookups concurrently.
// It never blocks a scan: each lookup is bounded and failures degrade silently
// to "unknown". IP-literal targets are skipped (RDAP/DBL are domain-oriented).
func gatherReputation(ctx context.Context, env *scan.Env, domain string) netResult {
	nr := netResult{ageDays: -1}
	if domain == "" || net.ParseIP(domain) != nil {
		return nr
	}
	ctx, cancel := context.WithTimeout(ctx, 14*time.Second)
	defer cancel()

	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		ageDays   = -1
		regDate   string
		registrar string
		lists     []string
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if reg, regName, ok := rdapRegistration(ctx, env, domain); ok {
			d := int(time.Since(reg).Hours() / 24)
			if d < 0 {
				d = 0
			}
			mu.Lock()
			ageDays, regDate, registrar = d, reg.Format("2006-01-02"), regName
			mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		found := blocklistLookup(ctx, env, domain)
		mu.Lock()
		lists = append(lists, found...)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if urlhausListed(ctx, env, domain) {
			mu.Lock()
			lists = append(lists, "URLhaus")
			mu.Unlock()
		}
	}()

	wg.Wait()
	nr.ageDays, nr.regDate, nr.blocklists, nr.registrar = ageDays, regDate, lists, registrar

	if s, ok := ageToSignal(ageDays); ok {
		nr.signals = append(nr.signals, s)
	}
	if len(lists) > 0 {
		// Multiple independent listings are near-certain malice.
		w := 40
		if len(lists) >= 2 {
			w = 55
		}
		nr.signals = append(nr.signals, signal{
			code: "blocklist", weight: w,
			detail: "The domain is listed on reputable abuse/phishing/malware blocklists (" + strings.Join(lists, ", ") + ").",
		})
	}
	return nr
}

// ageToSignal maps a domain age in days to a weighted risk signal. Freshly
// registered domains are the workhorse of phishing campaigns; aged domains are
// a mild positive signal (no signal emitted — absence lowers the total score).
//
// Windows are calibrated to modern kit lifecycles: many investment/AI scams
// run for 3–6 months before rotating domains, so a 99-day-old "future-aihub"
// style site must still score as young.
func ageToSignal(days int) (signal, bool) {
	switch {
	case days < 0:
		return signal{}, false // unknown
	case days <= 7:
		return signal{"domain-new", 32, "The domain was registered within the last week — a hallmark of throwaway phishing sites."}, true
	case days <= 30:
		return signal{"domain-new", 25, "The domain was registered within the last month, which is common for scam sites."}, true
	case days <= 90:
		return signal{"domain-young", 16, "The domain is less than three months old — still in the peak window for phishing kits."}, true
	case days <= 180:
		return signal{"domain-young", 10, "The domain is less than six months old. Many investment and crypto scams rotate domains on this cadence."}, true
	case days <= 365:
		return signal{"domain-young", 5, "The domain is under a year old. Treat unsolicited login or payment requests with caution."}, true
	default:
		return signal{}, false
	}
}

// --- RDAP -------------------------------------------------------------------

// rdapRegistration fetches the domain's RDAP record via rdap.org (which
// bootstraps to the authoritative registry) and returns its registration date
// and registrar name when available.
func rdapRegistration(ctx context.Context, env *scan.Env, domain string) (time.Time, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		return time.Time{}, "", false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := env.HTTP.Do(req)
	if err != nil {
		return time.Time{}, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return time.Time{}, "", false
	}
	return parseRDAPRegistration(body)
}

// parseRDAPRegistration extracts the "registration" event date and registrar
// from an RDAP response. It is pure so it can be unit-tested without network.
func parseRDAPRegistration(body []byte) (time.Time, string, bool) {
	var doc struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles     []string `json:"roles"`
			VcardArray []any   `json:"vcardArray"`
		} `json:"entities"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return time.Time{}, "", false
	}
	var reg time.Time
	ok := false
	for _, e := range doc.Events {
		if strings.EqualFold(e.Action, "registration") {
			if t, parsed := parseRDAPDate(e.Date); parsed {
				reg, ok = t, true
				break
			}
		}
	}
	if !ok {
		return time.Time{}, "", false
	}
	registrar := ""
	for _, ent := range doc.Entities {
		isReg := false
		for _, r := range ent.Roles {
			if strings.EqualFold(r, "registrar") {
				isReg = true
				break
			}
		}
		if !isReg {
			continue
		}
		registrar = vcardFN(ent.VcardArray)
		if registrar != "" {
			break
		}
	}
	return reg, registrar, true
}

// vcardFN pulls the FN (formatted name) from a jCard vcardArray blob.
func vcardFN(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	arr, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, raw := range arr {
		row, ok := raw.([]any)
		if !ok || len(row) < 4 {
			continue
		}
		name, _ := row[0].(string)
		if !strings.EqualFold(name, "fn") {
			continue
		}
		if s, ok := row[3].(string); ok {
			return s
		}
	}
	return ""
}

var rdapDateLayouts = []string{
	time.RFC3339, time.RFC3339Nano,
	"2006-01-02T15:04:05Z", "2006-01-02T15:04:05",
	"2006-01-02 15:04:05", "2006-01-02",
}

func parseRDAPDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range rdapDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// --- Blocklists -------------------------------------------------------------

var domainBlocklists = []struct{ zone, name string }{
	{"dbl.spamhaus.org", "Spamhaus DBL"},
	{"multi.surbl.org", "SURBL"},
	{"black.uribl.com", "URIBL"},
	{"multi.uribl.com", "URIBL multi"},
	{"uribl.spameatingmonkey.net", "SEM URIBL"},
}

// blocklistLookup queries each domain blocklist over DoH and returns the names
// of lists that genuinely flag the domain. Error/again codes (e.g. Spamhaus'
// public-resolver rejection at 127.255.255.x) are ignored to avoid false
// positives.
func blocklistLookup(ctx context.Context, env *scan.Env, domain string) []string {
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		found []string
	)
	for _, bl := range domainBlocklists {
		wg.Add(1)
		go func(zone, name string) {
			defer wg.Done()
			answers := netutil.LookupDoH(ctx, env.HTTP, env.UserAgent, domain+"."+zone, "A")
			if blocklistListed(answers) {
				mu.Lock()
				found = append(found, name)
				mu.Unlock()
			}
		}(bl.zone, bl.name)
	}
	wg.Wait()
	return found
}

// blocklistListed reports whether DoH answers represent a genuine listing.
// A real listing is a 127.0.x.y response; 127.255.255.x is an error/refusal and
// 127.0.0.1 / empty means not listed.
func blocklistListed(answers []string) bool {
	for _, a := range answers {
		ip := net.ParseIP(strings.TrimSpace(a))
		v4 := ip.To4()
		if v4 == nil || v4[0] != 127 {
			continue
		}
		if v4[1] == 255 { // 127.255.255.x => error/again, not a listing
			continue
		}
		if v4[3] >= 2 { // 127.0.x.>=2 => listed
			return true
		}
	}
	return false
}

// --- URLhaus (abuse.ch) -----------------------------------------------------

// urlhausListed queries the free URLhaus host API. A "online" or "offline"
// listed host is treated as a malware/phish indicator. Failures return false.
func urlhausListed(ctx context.Context, env *scan.Env, domain string) bool {
	form := url.Values{"host": {domain}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://urlhaus-api.abuse.ch/v1/host/", strings.NewReader(form))
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := env.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		return false
	}
	return parseURLHausHost(body)
}

// parseURLHausHost is pure JSON parsing for the URLhaus host endpoint.
func parseURLHausHost(body []byte) bool {
	var doc struct {
		QueryStatus string `json:"query_status"`
		URLCount    any    `json:"url_count"`
		URLs        []any  `json:"urls"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false
	}
	if !strings.EqualFold(doc.QueryStatus, "ok") {
		return false
	}
	if len(doc.URLs) > 0 {
		return true
	}
	// Some responses only populate url_count.
	switch v := doc.URLCount.(type) {
	case float64:
		return v > 0
	case string:
		return v != "" && v != "0"
	}
	return false
}
