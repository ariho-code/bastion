// Package abuse holds anti-abuse controls that go beyond SSRF safety: input
// validation that rejects suspicious targets, and a per-target cooldown so the
// scanner can never be weaponized to repeatedly hammer a single victim.
package abuse

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// blockedTargetPorts are service ports we refuse to point the HTTP fetcher at.
// (The port scanner still inspects them; this only stops the page-fetch/probe
// modules from being aimed at non-web services.)
var blockedTargetPorts = map[string]bool{
	"22": true, "23": true, "25": true, "110": true, "143": true, "465": true,
	"587": true, "993": true, "995": true, "3306": true, "5432": true, "6379": true,
	"27017": true, "3389": true, "5900": true, "11211": true, "9200": true,
}

// Validate applies abuse-prevention rules that complement the SSRF guard.
func Validate(t *scan.Target) error {
	host := t.Host
	if host == "" {
		return fmt.Errorf("missing hostname")
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 {
			return fmt.Errorf("hostname label is too long")
		}
	}
	if t.URL != nil && t.URL.User != nil {
		return fmt.Errorf("URLs with embedded credentials are not allowed")
	}
	if p := t.Port; p != "" && blockedTargetPorts[p] {
		return fmt.Errorf("port %s is a non-web service port; deep scans reach it via the port scanner", p)
	}
	return nil
}

// Cooldown enforces a minimum interval between scans of the same host, so the
// engine can't be used to flood a target with repeated scans.
type Cooldown struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Duration
}

// NewCooldown creates a Cooldown with the given window (<=0 disables it).
func NewCooldown(window time.Duration) *Cooldown {
	return &Cooldown{last: map[string]time.Time{}, window: window}
}

// Check reports whether a scan of host is allowed now. When it returns false,
// retryAfter is the seconds the caller should wait. A permitted check records
// the attempt so the next one is gated.
func (c *Cooldown) Check(host string) (ok bool, retryAfter int) {
	if c.window <= 0 {
		return true, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if t, seen := c.last[host]; seen {
		if elapsed := now.Sub(t); elapsed < c.window {
			return false, int((c.window - elapsed).Seconds()) + 1
		}
	}
	c.last[host] = now

	// Opportunistic prune so the map can't grow unbounded.
	if len(c.last) > 10000 {
		for k, v := range c.last {
			if now.Sub(v) > c.window {
				delete(c.last, k)
			}
		}
	}
	return true, 0
}
