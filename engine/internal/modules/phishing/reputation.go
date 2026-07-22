package phishing

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// netResult holds the network-derived reputation of a domain: how old it is
// (a brand-new domain is a top phishing signal) and whether it appears on
// domain blocklists. It also carries the risk signals these produce so they can
// be folded into the lexical assessment.
type netResult struct {
	signals    []signal
	ageDays    int      // -1 when unknown
	regDate    string   // YYYY-MM-DD, "" when unknown
	blocklists []string // reputable lists that flagged the domain
}

// gatherReputation runs the RDAP age lookup and blocklist checks concurrently.
// It never blocks a scan: each lookup is bounded and failures degrade silently
// to "unknown". IP-literal targets are skipped (RDAP/DBL are domain-oriented).
func gatherReputation(ctx context.Context, env *scan.Env, domain string) netResult {
	nr := netResult{ageDays: -1}
	if domain == "" || net.ParseIP(domain) != nil {
		return nr
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		ageDays  = -1
		regDate  string
		lists    []string
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if reg, ok := rdapRegistration(ctx, env, domain); ok {
			d := int(time.Since(reg).Hours() / 24)
			if d < 0 {
				d = 0
			}
			mu.Lock()
			ageDays, regDate = d, reg.Format("2006-01-02")
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

	wg.Wait()
	nr.ageDays, nr.regDate, nr.blocklists = ageDays, regDate, lists

	if s, ok := ageToSignal(ageDays); ok {
		nr.signals = append(nr.signals, s)
	}
	if len(lists) > 0 {
		nr.signals = append(nr.signals, signal{
			code: "blocklist", weight: 40,
			detail: "The domain is listed on reputable abuse/phishing blocklists (" + strings.Join(lists, ", ") + ").",
		})
	}
	return nr
}

// ageToSignal maps a domain age in days to a weighted risk signal. Freshly
// registered domains are the workhorse of phishing campaigns; aged domains are
// a mild positive signal (no signal emitted — absence lowers the total score).
func ageToSignal(days int) (signal, bool) {
	switch {
	case days < 0:
		return signal{}, false // unknown
	case days <= 7:
		return signal{"domain-new", 30, "The domain was registered within the last week — a hallmark of throwaway phishing sites."}, true
	case days <= 30:
		return signal{"domain-new", 22, "The domain was registered within the last month, which is common for scam sites."}, true
	case days <= 90:
		return signal{"domain-young", 12, "The domain is less than three months old."}, true
	default:
		return signal{}, false
	}
}

// --- RDAP -------------------------------------------------------------------

// rdapRegistration fetches the domain's RDAP record via rdap.org (which
// bootstraps to the authoritative registry) and returns its registration date.
func rdapRegistration(ctx context.Context, env *scan.Env, domain string) (time.Time, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/domain/"+domain, nil)
	if err != nil {
		return time.Time{}, false
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := env.HTTP.Do(req)
	if err != nil {
		return time.Time{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return time.Time{}, false
	}
	return parseRDAPRegistration(body)
}

// parseRDAPRegistration extracts the "registration" event date from an RDAP
// response. It is pure so it can be unit-tested without network. RDAP dates are
// RFC3339, but registries vary slightly, so a few layouts are attempted.
func parseRDAPRegistration(body []byte) (time.Time, bool) {
	var doc struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return time.Time{}, false
	}
	for _, e := range doc.Events {
		if strings.EqualFold(e.Action, "registration") {
			if t, ok := parseRDAPDate(e.Date); ok {
				return t, true
			}
		}
	}
	return time.Time{}, false
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
