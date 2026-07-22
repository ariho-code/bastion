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

	// Vertical selects industry pack: banking | ecommerce | saas | scam | general.
	// Active modules use this to prioritize paths and checks for that industry.
	Vertical string `json:"vertical,omitempty"`

	// Session enables authenticated Active scanning for owners who paste a
	// browser session cookie / Authorization header from *their* account.
	// Never logged in full by modules; only used for outbound probes.
	Session *Session `json:"session,omitempty"`

	// Intensity: safe | thorough | aggressive (default safe).
	// Aggressive unlocks higher probe budgets and the bounded load module —
	// still single-origin, hard-capped, and scope-respecting (not a botnet).
	Intensity string `json:"intensity,omitempty"`
	// Stealth randomizes delays and User-Agents so authorized tests mimic
	// low-and-slow recon (helps validate WAF/bot rules). Not multi-IP hopping;
	// owners who need multi-egress must run workers on their own network.
	Stealth *bool `json:"stealth,omitempty"`
	// JitterMs max random extra delay per probe when stealth is on (0 = auto).
	JitterMs int `json:"jitterMs,omitempty"`
	// ConsentLoad must be true with intensity=aggressive to run the bounded
	// load-resilience suite (explicit owner opt-in).
	ConsentLoad bool `json:"consentLoad,omitempty"`
}

// Session is an owner-supplied authenticated context for Active DAST.
// Only accepted when the target is ownership-verified.
type Session struct {
	// Cookie is a raw Cookie header value (e.g. "session=abc; csrftoken=…").
	Cookie string `json:"cookie,omitempty"`
	// Authorization is a full Authorization header (e.g. "Bearer eyJ…").
	Authorization string `json:"authorization,omitempty"`
	// ExtraHeaders are additional request headers (name → value), capped.
	ExtraHeaders map[string]string `json:"extraHeaders,omitempty"`
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
	if o.Vertical != "" {
		out.Vertical = strings.ToLower(strings.TrimSpace(o.Vertical))
	}
	if o.Session != nil {
		out.Session = o.Session
	}
	if o.Intensity != "" {
		out.Intensity = strings.ToLower(strings.TrimSpace(o.Intensity))
	}
	if o.Stealth != nil {
		out.Stealth = o.Stealth
	}
	if o.JitterMs > 0 {
		out.JitterMs = o.JitterMs
	}
	if o.ConsentLoad {
		out.ConsentLoad = true
	}
	return out
}

// NormalizedIntensity returns safe|thorough|aggressive.
func (s Scope) NormalizedIntensity() string {
	switch strings.ToLower(strings.TrimSpace(s.Intensity)) {
	case "thorough", "medium":
		return "thorough"
	case "aggressive", "redteam", "red-team", "full":
		return "aggressive"
	default:
		return "safe"
	}
}

// IsStealth reports whether stealth/jitter mode is enabled (default true for active).
func (s Scope) IsStealth() bool {
	if s.Stealth == nil {
		return true // default on for authorized Active — quieter, more realistic recon
	}
	return *s.Stealth
}

// ProbeBudget returns (maxRequests, concurrency, baseDelayMs) for Active modules.
func (s Scope) ProbeBudget() (maxReq, concurrency, delayMs int) {
	switch s.NormalizedIntensity() {
	case "aggressive":
		maxReq, concurrency, delayMs = 900, 12, 15
	case "thorough":
		maxReq, concurrency, delayMs = 600, 8, 25
	default:
		maxReq, concurrency, delayMs = 400, 6, 40
	}
	if s.MaxRequests > 0 && s.MaxRequests < maxReq {
		maxReq = s.MaxRequests
	}
	if s.RequestDelayMs > 0 {
		delayMs = s.RequestDelayMs
	}
	// Hard ceiling — never unbounded.
	if maxReq > 1200 {
		maxReq = 1200
	}
	if concurrency > 16 {
		concurrency = 16
	}
	return maxReq, concurrency, delayMs
}

// NormalizedVertical returns a known vertical or "general".
func (s Scope) NormalizedVertical() string {
	switch strings.ToLower(strings.TrimSpace(s.Vertical)) {
	case "banking", "bank", "fintech":
		return "banking"
	case "ecommerce", "e-commerce", "shop", "retail":
		return "ecommerce"
	case "saas", "b2b", "software":
		return "saas"
	case "scam", "phishing", "fraud":
		return "scam"
	default:
		return "general"
	}
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
