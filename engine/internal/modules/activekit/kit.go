// Package activekit provides shared, precision-first helpers for ownership-gated
// Active DAST modules: parameter discovery, scoped HTTP, unique canaries, and
// safe response analysis. Modules must never issue destructive payloads or
// bulk credential stuffing — detection only, with corroboration.
package activekit

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

const maxBody = 96 << 10

// Budget tracks speculative request counts under Scope.MaxRequests.
type Budget struct {
	max  int64
	used int64
}

func NewBudget(scope scan.Scope) *Budget {
	max, _, _ := scope.ProbeBudget()
	if scope.MaxRequests > 0 && int64(scope.MaxRequests) < int64(max) {
		max = scope.MaxRequests
	}
	return &Budget{max: int64(max)}
}

// StealthUserAgents rotate to mimic diverse legitimate clients during authorized tests.
var StealthUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/122.0.0.0",
}

func (b *Budget) Take() bool {
	if b == nil {
		return true
	}
	n := atomic.AddInt64(&b.used, 1)
	return n <= b.max
}

func (b *Budget) Used() int64 {
	if b == nil {
		return 0
	}
	return atomic.LoadInt64(&b.used)
}

// Canary returns a unique probe marker unlikely to appear in normal pages.
func Canary(prefix string) string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return prefix + hex.EncodeToString(buf[:])
}

// Param is a discovered injection point (query or form field).
type Param struct {
	Name   string
	In     string // "query" | "body"
	Method string // GET / POST
	Action string // absolute URL to submit
	Value  string // sample original value
}

// Surface is the set of testable endpoints extracted from the shared page.
type Surface struct {
	Base   string
	Params []Param
	Forms  []Form
}

// Form is an HTML form discovered on the page.
type Form struct {
	Action string
	Method string
	Fields map[string]string
	// AuthLike is true when the form looks like a login (password field present).
	AuthLike bool
}

var (
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	attrRe  = regexp.MustCompile(`(?i)\b(action|method)\s*=\s*["']?([^"'\s>]+)`)
	inputRe = regexp.MustCompile(`(?is)<input\b([^>]*)/?>`)
	nameRe  = regexp.MustCompile(`(?i)\bname\s*=\s*["']?([^"'\s>]+)`)
	typeRe  = regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^"'\s>]+)`)
	valRe   = regexp.MustCompile(`(?i)\bvalue\s*=\s*["']?([^"'\s>]*)`)
	hrefRe  = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)
)

// Discover builds a parameter surface from the shared page + URL query.
func Discover(ctx context.Context, t *scan.Target, env *scan.Env) Surface {
	base := "https://" + t.Host
	page := env.Page(ctx, t)
	body := ""
	if page != nil && page.Err == nil {
		if page.FinalURL != "" {
			if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
				base = u.Scheme + "://" + u.Host
			}
		}
		body = page.Body
	}
	s := Surface{Base: base}

	// Query params on the target URL itself.
	if t.URL != nil {
		for k, vs := range t.URL.Query() {
			v := ""
			if len(vs) > 0 {
				v = vs[0]
			}
			s.Params = append(s.Params, Param{
				Name: k, In: "query", Method: http.MethodGet,
				Action: base + t.URL.Path, Value: v,
			})
		}
	}

	// Forms.
	for _, m := range formRe.FindAllStringSubmatch(body, 30) {
		attrs, inner := m[1], m[2]
		action, method := "", "GET"
		for _, a := range attrRe.FindAllStringSubmatch(attrs, 8) {
			switch strings.ToLower(a[1]) {
			case "action":
				action = a[2]
			case "method":
				method = strings.ToUpper(a[2])
			}
		}
		if action == "" {
			action = t.URL.Path
			if action == "" {
				action = "/"
			}
		}
		abs := resolveURL(base, action)
		if abs == "" {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil {
			continue
		}
		if !t.Scope.HostAllowed(u.Hostname()) && u.Hostname() != "" && u.Hostname() != t.Host {
			continue
		}
		if !t.Scope.PathAllowed(u.Path) {
			continue
		}
		fields := map[string]string{}
		authLike := false
		for _, in := range inputRe.FindAllStringSubmatch(inner, 40) {
			ia := in[1]
			n := first(nameRe, ia)
			if n == "" {
				continue
			}
			ty := strings.ToLower(first(typeRe, ia))
			if ty == "submit" || ty == "button" || ty == "image" || ty == "file" {
				continue
			}
			if ty == "password" {
				authLike = true
			}
			fields[n] = first(valRe, ia)
			s.Params = append(s.Params, Param{
				Name: n, In: "body", Method: method, Action: abs, Value: fields[n],
			})
		}
		s.Forms = append(s.Forms, Form{Action: abs, Method: method, Fields: fields, AuthLike: authLike})
	}

	// Query strings embedded in same-host links (common for id=, page=, q=).
	for _, hm := range hrefRe.FindAllStringSubmatch(body, 80) {
		href := hm[1]
		if strings.HasPrefix(href, "#") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "javascript:") {
			continue
		}
		abs := resolveURL(base, href)
		u, err := url.Parse(abs)
		if err != nil || u.RawQuery == "" {
			continue
		}
		if u.Hostname() != "" && u.Hostname() != t.Host && !strings.HasSuffix(u.Hostname(), "."+t.Domain) {
			continue
		}
		if !t.Scope.PathAllowed(u.Path) {
			continue
		}
		for k, vs := range u.Query() {
			v := ""
			if len(vs) > 0 {
				v = vs[0]
			}
			// Prefer common injectable param names to keep precision high.
			if !interestingParam(k) {
				continue
			}
			s.Params = append(s.Params, Param{
				Name: k, In: "query", Method: http.MethodGet,
				Action: u.Scheme + "://" + u.Host + u.Path, Value: v,
			})
		}
	}

	s.Params = dedupeParams(s.Params)
	if len(s.Params) > 40 {
		s.Params = s.Params[:40]
	}
	return s
}

func interestingParam(name string) bool {
	n := strings.ToLower(name)
	keys := []string{
		"id", "page", "q", "query", "search", "s", "keyword", "cat", "category",
		"file", "path", "dir", "folder", "doc", "document", "url", "uri", "redirect",
		"next", "return", "returnurl", "continue", "dest", "destination", "ref",
		"user", "userid", "uid", "item", "product", "order", "sort", "filter",
		"lang", "locale", "view", "template", "include", "load", "data", "json",
		"callback", "api", "token", "code", "email", "name",
	}
	for _, k := range keys {
		if n == k || strings.Contains(n, k) {
			return true
		}
	}
	return false
}

func dedupeParams(in []Param) []Param {
	seen := map[string]bool{}
	var out []Param
	for _, p := range in {
		key := p.Method + "|" + p.Action + "|" + p.Name + "|" + p.In
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func first(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

// ProbeResult is a single HTTP probe outcome.
type ProbeResult struct {
	Status int
	Body   string
	Header http.Header
	URL    string
	Err    error
}

// Client wraps scoped, budgeted HTTP for Active modules.
type Client struct {
	Env    *scan.Env
	Target *scan.Target
	Budget *Budget
	http   *http.Client
	delay  time.Duration
	mu     sync.Mutex
}

func NewClient(env *scan.Env, t *scan.Target) *Client {
	_, _, delayMs := t.Scope.ProbeBudget()
	d := time.Duration(delayMs) * time.Millisecond
	return &Client{Env: env, Target: t, Budget: NewBudget(t.Scope), http: probeClient(env), delay: d}
}

// probeClient derives a NON-redirect-following client from the environment's
// SSRF-guarded client. DAST probes must observe the raw response — the Location
// header, status code and Set-Cookie of a 3xx — instead of chasing the redirect
// (which is how open-redirect, auth and CSRF checks actually detect issues). It
// reuses the guarded Transport, so SSRF protection is fully preserved.
func probeClient(env *scan.Env) *http.Client {
	base := http.DefaultClient
	if env != nil && env.HTTP != nil {
		base = env.HTTP
	}
	dup := *base // shallow copy keeps the guarded Transport
	dup.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &dup
}

func (c *Client) stealthSleep() {
	base := c.delay
	if !c.Target.Scope.IsStealth() {
		time.Sleep(base)
		return
	}
	// Low-and-slow jitter: base + [0, jitter]
	j := c.Target.Scope.JitterMs
	if j <= 0 {
		j = 120
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	extra := time.Duration(int(binary.BigEndian.Uint16(b[:]))%j) * time.Millisecond
	time.Sleep(base + extra)
}

func (c *Client) pickUA() string {
	if !c.Target.Scope.IsStealth() {
		return c.Env.UserAgent
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	return StealthUserAgents[int(b[0])%len(StealthUserAgents)]
}

// DoGET issues a GET with query overrides on action.
func (c *Client) DoGET(ctx context.Context, action string, query map[string]string) ProbeResult {
	u, err := url.Parse(action)
	if err != nil {
		return ProbeResult{Err: err}
	}
	if !c.Target.Scope.PathAllowed(u.Path) {
		return ProbeResult{Err: errOutOfScope}
	}
	q := u.Query()
	for k, v := range query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return c.do(ctx, http.MethodGet, u.String(), "", "")
}

// DoForm submits application/x-www-form-urlencoded fields.
func (c *Client) DoForm(ctx context.Context, method, action string, fields map[string]string) ProbeResult {
	u, err := url.Parse(action)
	if err != nil {
		return ProbeResult{Err: err}
	}
	if !c.Target.Scope.PathAllowed(u.Path) {
		return ProbeResult{Err: errOutOfScope}
	}
	method = strings.ToUpper(method)
	if method == "" {
		method = http.MethodPost
	}
	vals := url.Values{}
	for k, v := range fields {
		vals.Set(k, v)
	}
	if method == http.MethodGet {
		u.RawQuery = vals.Encode()
		return c.do(ctx, http.MethodGet, u.String(), "", "")
	}
	return c.do(ctx, method, u.String(), vals.Encode(), "application/x-www-form-urlencoded")
}

var errOutOfScope = &scopeError{}

type scopeError struct{}

func (e *scopeError) Error() string { return "path outside scan scope" }

func (c *Client) do(ctx context.Context, method, rawURL, body, ct string) ProbeResult {
	if !c.Budget.Take() {
		return ProbeResult{Err: errBudget}
	}
	c.mu.Lock()
	c.stealthSleep()
	c.mu.Unlock()

	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return ProbeResult{Err: err}
	}
	req.Header.Set("User-Agent", c.pickUA())
	req.Header.Set("Accept", "text/html,application/json,*/*")
	// Always identify authorized Active probes so WAFs can allow-list them.
	req.Header.Set("X-Bastionscan-Probe", "active-dast")
	req.Header.Set("X-Bastionscan-Owner-Verified", "1")
	req.Header.Set("X-Bastionscan-Intensity", c.Target.Scope.NormalizedIntensity())
	for k, vs := range c.Env.SessionHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	client := c.http
	if client == nil {
		client = c.Env.HTTP
	}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Err: err, URL: rawURL}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return ProbeResult{
		Status: resp.StatusCode,
		Body:   string(b),
		Header: resp.Header.Clone(),
		URL:    rawURL,
	}
}

var errBudget = &budgetError{}

type budgetError struct{}

func (e *budgetError) Error() string { return "active probe request budget exhausted" }

// ContainsUnencoded reports whether marker appears literally in body
// (not HTML-entity encoded). High-precision XSS reflection check.
func ContainsUnencoded(body, marker string) bool {
	if marker == "" || body == "" {
		return false
	}
	if !strings.Contains(body, marker) {
		return false
	}
	// If only present as entity-encoded, not a reflection vuln we claim.
	enc := strings.ReplaceAll(marker, "<", "&lt;")
	enc = strings.ReplaceAll(enc, ">", "&gt;")
	enc = strings.ReplaceAll(enc, `"`, "&quot;")
	enc = strings.ReplaceAll(enc, "'", "&#39;")
	if strings.Contains(body, enc) && !strings.Contains(body, marker) {
		return false
	}
	return strings.Contains(body, marker)
}
