package scan

import (
	"path"
	"strings"
)

// Scope lets enterprise owners constrain what an Active-tier scan is allowed to
// touch. Empty fields mean "no restriction" (full allowed surface). Scope is
// only meaningful once ownership is verified — passive/deep scans ignore it.
//
// Design goals:
//   - prevent collateral damage (exclude /admin/prod, payment paths, partner APIs)
//   - disable whole probe families (e.g. skip authweak during a PCI window)
//   - hard caps on request volume so a misconfigured wordlist can't flood origin
type Scope struct {
	// IncludePaths, when non-empty, limits probes to URLs whose path matches
	// one of these prefixes (e.g. "/api/", "/login").
	IncludePaths []string `json:"includePaths,omitempty"`
	// ExcludePaths skips any probe whose path matches a prefix
	// (e.g. "/billing/", "/admin/production").
	ExcludePaths []string `json:"excludePaths,omitempty"`
	// ExcludeHosts skips alternate hosts (CDN, staging) if discovered.
	ExcludeHosts []string `json:"excludeHosts,omitempty"`
	// DisableModules is a set of module IDs the owner does not want run
	// (e.g. "authweak", "discovery").
	DisableModules []string `json:"disableModules,omitempty"`
	// EnableModules, when non-empty, is an allow-list: only these module IDs
	// run at Active level (plus always-on passive/deep modules).
	EnableModules []string `json:"enableModules,omitempty"`
	// MaxRequests caps speculative HTTP requests from Active modules (0 = default).
	MaxRequests int `json:"maxRequests,omitempty"`
	// RequestDelayMs inserts a pause between speculative probes (0 = default 25ms).
	RequestDelayMs int `json:"requestDelayMs,omitempty"`
	// SafeMode (default true when unset via API) keeps only detection-grade
	// probes — no multi-credential attempts, no destructive methods.
	SafeMode *bool `json:"safeMode,omitempty"`
}

// DefaultScope returns enterprise-safe defaults: safe mode on, modest caps.
func DefaultScope() Scope {
	sm := true
	return Scope{
		MaxRequests:    400,
		RequestDelayMs: 25,
		SafeMode:       &sm,
	}
}

// Merge overlays non-zero fields from o onto a copy of s.
func (s Scope) Merge(o Scope) Scope {
	out := s
	if len(o.IncludePaths) > 0 {
		out.IncludePaths = append([]string{}, o.IncludePaths...)
	}
	if len(o.ExcludePaths) > 0 {
		out.ExcludePaths = append([]string{}, o.ExcludePaths...)
	}
	if len(o.ExcludeHosts) > 0 {
		out.ExcludeHosts = append([]string{}, o.ExcludeHosts...)
	}
	if len(o.DisableModules) > 0 {
		out.DisableModules = append([]string{}, o.DisableModules...)
	}
	if len(o.EnableModules) > 0 {
		out.EnableModules = append([]string{}, o.EnableModules...)
	}
	if o.MaxRequests > 0 {
		out.MaxRequests = o.MaxRequests
	}
	if o.RequestDelayMs > 0 {
		out.RequestDelayMs = o.RequestDelayMs
	}
	if o.SafeMode != nil {
		out.SafeMode = o.SafeMode
	}
	return out
}

// IsSafe reports whether SafeMode is enabled (default true).
func (s Scope) IsSafe() bool {
	if s.SafeMode == nil {
		return true
	}
	return *s.SafeMode
}

// ModuleAllowed reports whether an Active module may run under this scope.
func (s Scope) ModuleAllowed(moduleID string) bool {
	id := strings.ToLower(moduleID)
	for _, d := range s.DisableModules {
		if strings.EqualFold(d, id) {
			return false
		}
	}
	if len(s.EnableModules) == 0 {
		return true
	}
	for _, e := range s.EnableModules {
		if strings.EqualFold(e, id) {
			return true
		}
	}
	return false
}

// PathAllowed reports whether a URL path is inside the configured scope.
func (s Scope) PathAllowed(rawPath string) bool {
	p := path.Clean("/" + strings.TrimSpace(rawPath))
	if p == "." {
		p = "/"
	}
	for _, ex := range s.ExcludePaths {
		if prefixMatch(p, ex) {
			return false
		}
	}
	if len(s.IncludePaths) == 0 {
		return true
	}
	for _, in := range s.IncludePaths {
		if prefixMatch(p, in) {
			return true
		}
	}
	return false
}

// HostAllowed reports whether a host is not on the exclusion list.
func (s Scope) HostAllowed(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, ex := range s.ExcludeHosts {
		if strings.EqualFold(strings.TrimSpace(ex), h) {
			return false
		}
	}
	return true
}

func prefixMatch(p, prefix string) bool {
	pre := path.Clean("/" + strings.TrimSpace(prefix))
	if pre == "/" {
		return true
	}
	if !strings.HasSuffix(pre, "/") {
		// exact or child path
		return p == pre || strings.HasPrefix(p, pre+"/")
	}
	return strings.HasPrefix(p, pre) || p+"/" == pre
}
