// Package netutil provides shared, safety-first network helpers for scanner
// modules — most importantly an SSRF guard that keeps the engine from being
// pointed at internal infrastructure.
package netutil

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Guard decides whether a host is safe to scan. It blocks loopback, private,
// link-local, and other non-public address space so the engine can't be abused
// to reach cloud metadata endpoints or internal services.
type Guard struct {
	AllowPrivate bool          // escape hatch for local development only
	Resolver     *net.Resolver // nil => default resolver
	Timeout      time.Duration
}

// NewGuard returns a Guard with production-safe defaults.
func NewGuard(allowPrivate bool) *Guard {
	return &Guard{AllowPrivate: allowPrivate, Timeout: 5 * time.Second}
}

var blockedHostSuffixes = []string{
	".local", ".internal", ".localhost", ".lan", ".home.arpa",
}
var blockedHostExact = map[string]bool{
	"localhost": true, "ip6-localhost": true, "ip6-loopback": true,
}

// Check validates a hostname (or IP literal) for safety. It resolves DNS names
// and rejects the host if any resolved address is non-public.
func (g *Guard) Check(ctx context.Context, host string) error {
	if g.AllowPrivate {
		return nil
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if blockedHostExact[h] {
		return fmt.Errorf("host %q is not publicly routable", host)
	}
	for _, suf := range blockedHostSuffixes {
		if strings.HasSuffix(h, suf) {
			return fmt.Errorf("host %q resolves to a private namespace", host)
		}
	}

	if ip := net.ParseIP(h); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("address %s is not publicly routable", ip)
		}
		return nil
	}

	res := g.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	rctx, cancel := context.WithTimeout(ctx, g.Timeout)
	defer cancel()
	ips, err := res.LookupIP(rctx, "ip", h)
	if err != nil {
		return fmt.Errorf("could not resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no addresses found for %q", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("host %q resolves to a non-public address (%s)", host, ip)
		}
	}
	return nil
}

// IsPublicIP reports whether an IP is publicly routable (safe to scan).
func IsPublicIP(ip net.IP) bool { return isPublicIP(ip) }

// ResolvePublicIPs resolves a host and returns only its publicly-routable
// addresses. It errors if the host resolves to nothing public — giving modules
// a single, SSRF-safe way to turn a hostname into dialable IPs.
func ResolvePublicIPs(ctx context.Context, res *net.Resolver, host string) ([]net.IP, error) {
	if res == nil {
		res = net.DefaultResolver
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPublicIP(ip) {
			return []net.IP{ip}, nil
		}
		return nil, fmt.Errorf("address %s is not publicly routable", ip)
	}
	ips, err := res.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, ip := range ips {
		if isPublicIP(ip) {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("host %q has no publicly-routable addresses", host)
	}
	return out, nil
}

// isPublicIP reports whether an IP is safe to connect to from a scanner.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10) and IETF benchmarking ranges.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 { // 192.0.0.0/24
			return false
		}
		if v4[0] == 198 && (v4[1]&0xfe) == 18 { // 198.18.0.0/15
			return false
		}
	}
	return true
}
