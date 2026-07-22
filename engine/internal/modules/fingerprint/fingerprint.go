// Package fingerprint identifies the technologies behind a site — CMS,
// framework, language, JS libraries, and any CDN/WAF at the edge — and flags
// version disclosure. It is a cornerstone of attack-surface mapping: you can't
// reason about a target's risk without knowing what it runs.
package fingerprint

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module performs passive technology fingerprinting via a single HTTP fetch.
type Module struct{}

func (m *Module) ID() string              { return "fingerprint" }
func (m *Module) Category() scan.Category { return scan.CategorySurface }
func (m *Module) MinLevel() int           { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Technology fingerprinting: CMS, framework, language, JS libraries, CDN/WAF, and version disclosure"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

const maxBody = 300 * 1024 // read at most 300KB of HTML

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	p, err := fetch(ctx, t, env)
	if err != nil {
		return []scan.Finding{{
			ID: "surface.fingerprint", Category: scan.CategorySurface,
			Title: "Technology fingerprint unavailable", Status: scan.StatusInfo,
			Severity: scan.SeverityInfo, Detail: "Could not fetch the site to fingerprint it.",
			Evidence: err.Error(),
		}}, nil
	}

	var findings []scan.Finding
	findings = append(findings, technologyFindings(p)...)
	findings = append(findings, edgeFinding(p))
	findings = append(findings, versionDisclosureFinding(p))
	return findings, nil
}

// --- HTTP probe --------------------------------------------------------------

type probe struct {
	status      int
	headers     http.Header
	cookieNames []string
	body        string
	generator   string
	finalURL    string
}

func fetch(ctx context.Context, t *scan.Target, env *scan.Env) (*probe, error) {
	// Prefer HTTPS; fall back to whatever the caller gave us.
	primary := *t.URL
	if primary.Scheme == "http" {
		primary.Scheme = "https"
	}
	urls := []string{primary.String()}
	if raw := t.URL.String(); raw != urls[0] {
		urls = append(urls, raw)
	}

	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", env.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
		resp, err := env.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		p := &probe{
			status:   resp.StatusCode,
			headers:  resp.Header,
			finalURL: resp.Request.URL.String(),
		}
		for _, c := range resp.Cookies() {
			p.cookieNames = append(p.cookieNames, c.Name)
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") || ct == "" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			p.body = string(body)
			p.generator = extractGenerator(p.body)
		}
		resp.Body.Close()
		return p, nil
	}
	return nil, lastErr
}

var generatorRe = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)

func extractGenerator(body string) string {
	if m := generatorRe.FindStringSubmatch(body); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// --- signatures (data-driven) ------------------------------------------------

type matcher func(p *probe) bool

type sig struct {
	tech  string
	kind  string
	match matcher
}

func header(name, pattern string) matcher {
	re := regexp.MustCompile("(?i)" + pattern)
	return func(p *probe) bool { return re.MatchString(p.headers.Get(name)) }
}
func headerPresent(name string) matcher {
	return func(p *probe) bool { return p.headers.Get(name) != "" }
}
func cookie(pattern string) matcher {
	re := regexp.MustCompile("(?i)" + pattern)
	return func(p *probe) bool {
		for _, n := range p.cookieNames {
			if re.MatchString(n) {
				return true
			}
		}
		return false
	}
}
func body(pattern string) matcher {
	re := regexp.MustCompile("(?i)" + pattern)
	return func(p *probe) bool { return re.MatchString(p.body) }
}
func generator(pattern string) matcher {
	re := regexp.MustCompile("(?i)" + pattern)
	return func(p *probe) bool { return p.generator != "" && re.MatchString(p.generator) }
}

// signatures is the extensible fingerprint database. Add a row to teach the
// engine a new technology — no logic changes required.
var signatures = []sig{
	{"WordPress", "CMS", body(`wp-content|wp-includes`)},
	{"WordPress", "CMS", generator(`WordPress`)},
	{"Drupal", "CMS", header("X-Generator", `Drupal`)},
	{"Drupal", "CMS", body(`sites/(all|default)/(themes|modules)`)},
	{"Joomla", "CMS", body(`/media/jui/|option=com_`)},
	{"Ghost", "CMS", generator(`Ghost`)},
	{"Shopify", "E-commerce", headerPresent("X-ShopId")},
	{"Shopify", "E-commerce", body(`cdn\.shopify\.com`)},
	{"Magento", "E-commerce", cookie(`^(frontend|X-Magento)`)},
	{"Wix", "Website Builder", headerPresent("X-Wix-Request-Id")},
	{"Squarespace", "Website Builder", body(`static\.squarespace\.com`)},
	{"Webflow", "Website Builder", generator(`Webflow`)},
	{"PHP", "Language", header("X-Powered-By", `PHP`)},
	{"PHP", "Language", cookie(`^PHPSESSID$`)},
	{"ASP.NET", "Framework", header("X-Powered-By", `ASP\.NET`)},
	{"ASP.NET", "Framework", headerPresent("X-AspNet-Version")},
	{"ASP.NET", "Framework", cookie(`^ASP\.NET_SessionId$`)},
	{"Laravel", "Framework", cookie(`^laravel_session$`)},
	{"Django", "Framework", cookie(`^(csrftoken|django)`)},
	{"Ruby on Rails", "Framework", cookie(`^_\w+_session$`)},
	{"Java Servlet", "Language", cookie(`^JSESSIONID$`)},
	{"Express", "Framework", header("X-Powered-By", `Express`)},
	{"Next.js", "Framework", header("X-Powered-By", `Next\.js`)},
	{"Next.js", "Framework", body(`/_next/static`)},
	{"Nuxt", "Framework", body(`__NUXT__|/_nuxt/`)},
	{"React", "JS Library", body(`data-reactroot|react-dom(\.min)?\.js|__REACT`)},
	{"Vue.js", "JS Library", body(`data-v-[0-9a-f]{8}|vue(\.min)?\.js`)},
	{"Angular", "JS Library", body(`ng-version=|angular(\.min)?\.js`)},
	{"jQuery", "JS Library", body(`jquery[-.][\d.]+(\.min)?\.js|/jquery\.js`)},
	{"Bootstrap", "UI Framework", body(`bootstrap(\.min)?\.(css|js)`)},
	{"Tailwind CSS", "UI Framework", body(`tailwindcss|tw-[a-z]`)},
	{"Google Analytics", "Analytics", body(`google-analytics\.com/(analytics|ga)\.js|googletagmanager\.com/gtag`)},
	{"Google Tag Manager", "Analytics", body(`googletagmanager\.com/gtm\.js`)},
	{"HubSpot", "Marketing", body(`js\.hs-scripts\.com|hubspot`)},
	{"Cloudflare Turnstile", "Bot Protection", body(`challenges\.cloudflare\.com/turnstile`)},
	{"reCAPTCHA", "Bot Protection", body(`google\.com/recaptcha`)},
}

func technologyFindings(p *probe) []scan.Finding {
	found := map[string]map[string]bool{} // kind -> set(tech)
	for _, s := range signatures {
		if s.match(p) {
			if found[s.kind] == nil {
				found[s.kind] = map[string]bool{}
			}
			found[s.kind][s.tech] = true
		}
	}
	// Server software from the Server header (best-effort, product name only).
	if srv := p.headers.Get("Server"); srv != "" {
		name := strings.SplitN(srv, "/", 2)[0]
		if name != "" {
			if found["Server"] == nil {
				found["Server"] = map[string]bool{}
			}
			found["Server"][name] = true
		}
	}

	if len(found) == 0 {
		return []scan.Finding{{
			ID: "surface.technologies", Category: scan.CategorySurface,
			Title: "No technologies fingerprinted", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "No known technology signatures matched. The site may be static or heavily proxied.",
		}}
	}

	kinds := make([]string, 0, len(found))
	for k := range found {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var parts []string
	for _, k := range kinds {
		techs := make([]string, 0, len(found[k]))
		for tch := range found[k] {
			techs = append(techs, tch)
		}
		sort.Strings(techs)
		parts = append(parts, k+": "+strings.Join(techs, ", "))
	}
	return []scan.Finding{{
		ID: "surface.technologies", Category: scan.CategorySurface,
		Title: "Technology stack detected", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
		Detail:   "Fingerprinting identified the technologies powering this site.",
		Evidence: strings.Join(parts, " · "),
	}}
}

// --- edge (CDN/WAF) detection ------------------------------------------------

type edgeSig struct {
	name  string
	match matcher
}

var edgeSignatures = []edgeSig{
	{"Cloudflare", func(p *probe) bool {
		return p.headers.Get("CF-RAY") != "" || strings.Contains(strings.ToLower(p.headers.Get("Server")), "cloudflare")
	}},
	{"Akamai", func(p *probe) bool {
		return p.headers.Get("X-Akamai-Transformed") != "" || strings.Contains(p.headers.Get("Server"), "AkamaiGHost")
	}},
	{"Sucuri", headerPresent("X-Sucuri-ID")},
	{"Imperva Incapsula", func(p *probe) bool {
		return p.headers.Get("X-Iinfo") != "" || strings.EqualFold(p.headers.Get("X-CDN"), "Incapsula")
	}},
	{"Amazon CloudFront", func(p *probe) bool {
		return p.headers.Get("X-Amz-Cf-Id") != "" || strings.Contains(strings.ToLower(p.headers.Get("Via")), "cloudfront")
	}},
	{"Fastly", func(p *probe) bool {
		return p.headers.Get("Fastly-Debug-Digest") != "" || strings.Contains(strings.ToLower(p.headers.Get("Via")), "fastly") || strings.Contains(strings.ToLower(p.headers.Get("X-Served-By")), "cache-")
	}},
	{"Vercel", func(p *probe) bool {
		return p.headers.Get("X-Vercel-Id") != "" || strings.Contains(p.headers.Get("Server"), "Vercel")
	}},
	{"Netlify", func(p *probe) bool {
		return p.headers.Get("X-NF-Request-Id") != "" || strings.Contains(p.headers.Get("Server"), "Netlify")
	}},
	{"AWS ELB/ALB", header("Server", `awselb`)},
	{"Google Frontend", header("Server", `gws|Google Frontend|ESF`)},
}

func edgeFinding(p *probe) scan.Finding {
	var detected []string
	for _, e := range edgeSignatures {
		if e.match(p) {
			detected = append(detected, e.name)
		}
	}
	f := scan.Finding{
		ID: "surface.edge", Category: scan.CategorySurface,
		Title: "Edge CDN / WAF", Severity: scan.SeverityInfo,
	}
	if len(detected) > 0 {
		f.Status = scan.StatusInfo
		f.Detail = "The site sits behind a CDN or WAF, which absorbs volumetric attacks and filters malicious traffic."
		f.Evidence = strings.Join(detected, ", ")
	} else {
		f.Status = scan.StatusInfo
		f.Detail = "No CDN or WAF was detected at the edge. A WAF/CDN adds DDoS protection and request filtering."
		f.Fix = "Consider fronting the origin with a CDN/WAF (Cloudflare, Fastly, AWS CloudFront)."
	}
	return f
}

// --- version disclosure ------------------------------------------------------

var versionRe = regexp.MustCompile(`\d+\.\d+`)

func versionDisclosureFinding(p *probe) scan.Finding {
	var leaks []string
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if v := p.headers.Get(h); v != "" && versionRe.MatchString(v) {
			leaks = append(leaks, h+": "+v)
		}
	}
	f := scan.Finding{
		ID: "disclosure.tech.version", Category: scan.CategoryDisclosure,
		Title: "Software version disclosure", MaxPoints: 8,
		Reference: "https://owasp.org/www-project-web-security-testing-guide/",
	}
	if len(leaks) > 0 {
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 0
		f.Detail = "Response headers reveal exact software versions, letting attackers match known CVEs to your stack."
		f.Evidence = strings.Join(leaks, " · ")
		f.Fix = "Strip or generalize version tokens (e.g. ServerTokens Prod, remove X-Powered-By)."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 8
		f.Detail = "No precise software versions are disclosed in response headers."
	}
	return f
}
