// Package cors detects Cross-Origin Resource Sharing misconfigurations — one of
// the most common and highest-impact web access-control flaws. It probes the
// target with several crafted Origin headers and inspects the returned
// Access-Control-Allow-Origin / Allow-Credentials policy. Every probe is a plain
// read (a GET, then an OPTIONS preflight fallback); nothing is written, so this
// runs safely against any target at the Deep profile.
package cors

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module probes cross-origin access-control policy.
type Module struct{}

func (m *Module) ID() string              { return "cors" }
func (m *Module) Category() scan.Category { return scan.CategorySurface }
func (m *Module) MinLevel() int           { return scan.ProfileDeep.Level }
func (m *Module) Description() string {
	return "CORS misconfiguration: reflected/null-origin trust, wildcard, and credentialed cross-origin exposure"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

// The origins we test with. The arbitrary origin proves blanket reflection; the
// look-alike proves naive prefix/substring matching; "null" proves the classic
// sandboxed-iframe bypass.
const (
	arbitraryOrigin = "https://cors-probe.bastionscan.com"
	nullOrigin      = "null"
)

// outcome is the CORS policy the server revealed for one probed Origin.
type outcome struct {
	acao  string // Access-Control-Allow-Origin value returned
	creds bool   // Access-Control-Allow-Credentials: true
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	base := "https://" + t.Host
	if page := env.Page(ctx, t); page.Err == nil && page.FinalURL != "" {
		if u, err := url.Parse(page.FinalURL); err == nil && u.Host != "" {
			base = u.Scheme + "://" + u.Host + "/"
		}
	}

	lookAlike := "https://" + t.Domain + ".cors-probe.bastionscan.com"
	arb := probe(ctx, env, base, arbitraryOrigin)
	null := probe(ctx, env, base, nullOrigin)
	look := probe(ctx, env, base, lookAlike)

	return []scan.Finding{evaluate(arbitraryOrigin, lookAlike, arb, null, look)}, nil
}

// probe issues a simple cross-origin GET and, if that surfaces no CORS headers,
// an OPTIONS preflight — some APIs only answer the preflight.
func probe(ctx context.Context, env *scan.Env, target, origin string) outcome {
	if o := doProbe(ctx, env, http.MethodGet, target, origin, false); o.acao != "" {
		return o
	}
	return doProbe(ctx, env, http.MethodOptions, target, origin, true)
}

func doProbe(ctx context.Context, env *scan.Env, method, target, origin string, preflight bool) outcome {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return outcome{}
	}
	req.Header.Set("User-Agent", env.UserAgent)
	req.Header.Set("Origin", origin)
	if preflight {
		req.Header.Set("Access-Control-Request-Method", "GET")
	}
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return outcome{}
	}
	defer resp.Body.Close()
	return outcome{
		acao:  strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin")),
		creds: strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true"),
	}
}

// evaluate turns the probe outcomes into a single graded finding. It is a pure
// function of the observed policy so it can be unit-tested without a network.
func evaluate(arbOrigin, lookAlike string, arb, null, look outcome) scan.Finding {
	f := scan.Finding{
		ID: "surface.cors", Category: scan.CategorySurface,
		Title: "Cross-Origin Resource Sharing (CORS)", MaxPoints: 10,
		Reference: "https://portswigger.net/web-security/cors",
	}

	reflectsArb := strings.EqualFold(arb.acao, arbOrigin)
	reflectsLook := strings.EqualFold(look.acao, lookAlike)
	trustsNull := strings.EqualFold(null.acao, "null")
	wildcard := arb.acao == "*" || null.acao == "*"

	switch {
	// Worst case: any origin is trusted *with credentials*. An attacker page can
	// make authenticated requests and read the responses — session/data theft.
	case reflectsArb && arb.creds:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityCritical, 0
		f.Detail = "The server reflects any Origin in Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true. Any malicious site can make authenticated cross-origin requests and read the responses — a direct path to account or data compromise."
		f.Evidence = "Origin: " + arbOrigin + " → Allow-Origin: " + arb.acao + "; Allow-Credentials: true"
		f.Fix = "Never reflect the Origin with credentials. Allow-list exact trusted origins, or drop Allow-Credentials for public data."
	case trustsNull && null.creds:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "The server trusts the \"null\" origin with credentials. Any sandboxed iframe or data:/file: document — trivially attacker-controlled — is granted credentialed cross-origin access."
		f.Evidence = "Origin: null → Allow-Origin: null; Allow-Credentials: true"
		f.Fix = "Remove \"null\" from the CORS allow-list; never pair it with Allow-Credentials."
	case reflectsLook && look.creds:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = "The CORS origin check appears to use naive prefix/substring matching: a look-alike attacker domain is trusted with credentials. An attacker who registers such a domain gains credentialed cross-origin access."
		f.Evidence = "Origin: " + lookAlike + " → Allow-Origin: " + look.acao + "; Allow-Credentials: true"
		f.Fix = "Match the Origin against an exact allow-list, not startsWith/contains on your domain."
	case reflectsArb || reflectsLook:
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 4
		f.Detail = "The server reflects arbitrary Origins in Access-Control-Allow-Origin (without credentials). Cross-origin sites can read responses to unauthenticated requests — a data-exposure risk for anything not meant to be fully public."
		f.Evidence = "Origin: " + arbOrigin + " → Allow-Origin: " + arb.acao
		f.Fix = "Reflect only allow-listed origins; return no CORS headers for private endpoints."
	case trustsNull:
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityMedium, 4
		f.Detail = "The server trusts the \"null\" origin (without credentials). This is still reachable by sandboxed documents and should not be allow-listed."
		f.Evidence = "Origin: null → Allow-Origin: null"
		f.Fix = "Remove \"null\" from the CORS allow-list."
	case wildcard:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 8
		f.Detail = "CORS is wildcard-open (Access-Control-Allow-Origin: *) but without credentials. This is the correct pattern for a genuinely public API; confirm no private data is served here."
		f.Evidence = "Allow-Origin: *"
	default:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "No permissive cross-origin policy was detected: the server does not reflect arbitrary, look-alike, or null origins."
	}
	return f
}
