package scan

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Env carries shared, safety-vetted dependencies into every module so modules
// never build their own (potentially unsafe) network clients. The engine
// constructs one Env per scan and passes it to each module's Run.
type Env struct {
	// HTTP is an SSRF-guarded client: it re-validates the resolved IP before
	// connecting and caps redirects. Modules that fetch content use this.
	HTTP *http.Client
	// Resolver performs DNS lookups (safe to share).
	Resolver *net.Resolver
	// UserAgent is the identifying UA string modules should send.
	UserAgent string

	pageOnce sync.Once
	page     *Page
}

// Page is the result of the target's primary HTTP fetch, retrieved once per
// scan and shared across every module that needs it (headers, cookies,
// fingerprint) — one request instead of four.
type Page struct {
	Status   int
	Header   http.Header
	Cookies  []*http.Cookie
	Body     string
	FinalURL string
	HTTPS    bool
	Err      error
}

const maxPageBody = 600 * 1024 // 600KB cap on HTML we read

// DefaultEnv returns an Env with stdlib defaults — handy for tests. Production
// callers build an Env with an SSRF-guarded client (see netutil.Guard).
func DefaultEnv() *Env {
	return &Env{
		HTTP:      http.DefaultClient,
		Resolver:  net.DefaultResolver,
		UserAgent: "BastionscanEngine/" + EngineVersion,
	}
}

// Page fetches the target's primary URL exactly once (HTTPS-first) and caches
// the result for all subsequent callers. The fetch is detached from the
// caller's cancellation so one module timing out can't invalidate the shared
// page for everyone; it still runs under its own bounded deadline.
func (e *Env) Page(ctx context.Context, t *Target) *Page {
	e.pageOnce.Do(func() {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		e.page = e.fetchPage(fctx, t)
	})
	return e.page
}

func (e *Env) fetchPage(ctx context.Context, t *Target) *Page {
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
		req.Header.Set("User-Agent", e.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
		resp, err := e.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		p := &Page{
			Status:   resp.StatusCode,
			Header:   resp.Header,
			Cookies:  resp.Cookies(),
			FinalURL: resp.Request.URL.String(),
			HTTPS:    strings.EqualFold(resp.Request.URL.Scheme, "https"),
		}
		if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") || ct == "" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPageBody))
			p.Body = string(body)
		}
		resp.Body.Close()
		return p
	}
	return &Page{Err: lastErr}
}
