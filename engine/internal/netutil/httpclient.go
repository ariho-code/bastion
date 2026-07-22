package netutil

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPClient returns an http.Client whose every connection is validated by the
// Guard. Crucially, it resolves and re-checks the destination IP at dial time
// and then connects to that exact IP — closing the DNS-rebinding (TOCTOU) hole
// where a hostname passes an up-front check but resolves to an internal address
// milliseconds later.
func (g *Guard) HTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		DialContext:           g.safeDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Every redirect hop is guarded too.
			return g.Check(req.Context(), req.URL.Hostname())
		},
	}
}

// safeDialContext resolves the host, verifies each candidate IP is publicly
// routable, and dials the validated IP directly.
func (g *Guard) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 15 * time.Second}
	if g.AllowPrivate {
		return dialer.DialContext(ctx, network, addr)
	}

	res := g.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ips, err := res.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	var lastErr error
	for _, ip := range ips {
		if !isPublicIP(ip) {
			lastErr = fmt.Errorf("host %q resolves to a non-public address (%s)", host, ip)
			continue
		}
		conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dialable public address for %q", host)
	}
	return nil, lastErr
}
