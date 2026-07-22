package scan

import (
	"net"
	"net/url"
	"strings"
)

// Target is a normalized scan subject shared across every module.
type Target struct {
	Raw      string   // exactly what the caller supplied
	URL      *url.URL // normalized absolute URL
	Host     string   // hostname (no port)
	Port     string   // explicit port, or "" for scheme default
	Domain   string   // registrable domain (eTLD+1, best-effort)
	Verified bool     // ownership-verified — unlocks Active-level modules
}

// twoLevelTLDs is a small, best-effort set of public suffixes with a second
// label. Replaced by a full Public Suffix List once the DNS modules land; kept
// tiny here to keep the first build dependency-free.
var twoLevelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true,
	"co.jp": true, "com.au": true, "net.au": true, "org.au": true, "co.nz": true,
	"co.za": true, "com.br": true, "co.in": true, "co.ke": true, "or.ke": true,
	"com.ng": true, "com.gh": true, "co.ug": true, "com.sg": true, "com.mx": true,
}

// NewTarget parses and normalizes raw user input into a Target. It does not
// perform any network I/O or safety checks — see netutil.Guard for that.
func NewTarget(raw string) (*Target, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, &ParseError{"please provide a URL or hostname to scan"}
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Hostname() == "" {
		return nil, &ParseError{"that doesn't look like a valid URL or hostname"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, &ParseError{"only http and https targets are supported"}
	}
	host := strings.ToLower(u.Hostname())
	return &Target{
		Raw:    raw,
		URL:    u,
		Host:   host,
		Port:   u.Port(),
		Domain: registrableDomain(host),
	}, nil
}

// PortOr returns the target's explicit port, or the supplied default.
func (t *Target) PortOr(def string) string {
	if t.Port != "" {
		return t.Port
	}
	return def
}

func registrableDomain(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	n := len(labels)
	if n <= 2 {
		return strings.Join(labels, ".")
	}
	last2 := labels[n-2] + "." + labels[n-1]
	if twoLevelTLDs[last2] && n >= 3 {
		return labels[n-3] + "." + last2
	}
	return last2
}

// ParseError is a user-facing input error (maps to HTTP 400).
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return e.Msg }
