// Package ports maps a target's exposed network surface. It performs a
// concurrent TCP-connect scan of common service ports (no raw sockets, no root)
// with a light banner grab, and flags dangerous services — databases, admin
// interfaces, cleartext protocols — that should never face the public internet.
package ports

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/netutil"
	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module runs a common-port TCP-connect scan. It is a Deep-profile capability
// because it touches more of the target than a passive fetch.
type Module struct{}

func (m *Module) ID() string              { return "ports" }
func (m *Module) Category() scan.Category { return scan.CategorySurface }
func (m *Module) MinLevel() int           { return scan.ProfileDeep.Level }
func (m *Module) Description() string {
	return "Common-port TCP scan with banner grab; flags dangerous publicly-exposed services"
}
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

const (
	dialTimeout    = 2500 * time.Millisecond
	bannerTimeout  = 800 * time.Millisecond
	scanConcurrency = 48
)

// portDef describes a well-known port and how much it matters when public.
// Adding a row extends coverage — no logic change needed.
type portDef struct {
	port     int
	service  string
	severity scan.Severity // severity when publicly reachable; Info = benign/expected
	why      string        // why exposure is risky (for risky ports)
}

var portDB = []portDef{
	{21, "FTP", scan.SeverityHigh, "cleartext file transfer; credentials sent unencrypted"},
	{22, "SSH", scan.SeverityLow, "remote admin surface; ensure key-only auth and fail2ban"},
	{23, "Telnet", scan.SeverityCritical, "cleartext remote shell; must never be public"},
	{25, "SMTP", scan.SeverityInfo, ""},
	{53, "DNS", scan.SeverityInfo, ""},
	{80, "HTTP", scan.SeverityInfo, ""},
	{110, "POP3", scan.SeverityLow, "cleartext mail retrieval"},
	{143, "IMAP", scan.SeverityLow, "cleartext mail access"},
	{389, "LDAP", scan.SeverityMedium, "directory service exposed; often unauthenticated"},
	{443, "HTTPS", scan.SeverityInfo, ""},
	{445, "SMB", scan.SeverityHigh, "file sharing; historically wormable (EternalBlue)"},
	{1433, "MSSQL", scan.SeverityCritical, "database directly reachable from the internet"},
	{2375, "Docker API", scan.SeverityCritical, "unauthenticated Docker daemon = full host takeover"},
	{3000, "Dev/Grafana", scan.SeverityMedium, "development or dashboard port exposed"},
	{3306, "MySQL", scan.SeverityCritical, "database directly reachable from the internet"},
	{3389, "RDP", scan.SeverityHigh, "remote desktop; prime brute-force / ransomware target"},
	{5000, "Dev/UPnP", scan.SeverityMedium, "development server exposed"},
	{5432, "PostgreSQL", scan.SeverityCritical, "database directly reachable from the internet"},
	{5601, "Kibana", scan.SeverityHigh, "analytics UI often unauthenticated"},
	{5900, "VNC", scan.SeverityHigh, "remote desktop; frequently weakly authenticated"},
	{6379, "Redis", scan.SeverityCritical, "often no auth by default; trivial data theft/RCE"},
	{8080, "HTTP-alt", scan.SeverityInfo, ""},
	{8443, "HTTPS-alt", scan.SeverityInfo, ""},
	{9200, "Elasticsearch", scan.SeverityCritical, "commonly unauthenticated; mass data exposure"},
	{11211, "Memcached", scan.SeverityHigh, "unauthenticated; DDoS amplification vector"},
	{15672, "RabbitMQ UI", scan.SeverityMedium, "management UI exposed (default guest/guest)"},
	{27017, "MongoDB", scan.SeverityCritical, "historically unauthenticated; mass data breaches"},
}

type openPort struct {
	def    portDef
	banner string
}

func (m *Module) Run(ctx context.Context, t *scan.Target, env *scan.Env) ([]scan.Finding, error) {
	ips, err := netutil.ResolvePublicIPs(ctx, env.Resolver, t.Host)
	if err != nil {
		return []scan.Finding{{
			ID: "surface.ports", Category: scan.CategorySurface,
			Title: "Port scan skipped", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
			Detail: "Could not resolve a public address to scan.", Evidence: err.Error(),
		}}, nil
	}
	ip := ips[0].String()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		open []openPort
		sem  = make(chan struct{}, scanConcurrency)
	)
	for _, d := range portDB {
		wg.Add(1)
		go func(d portDef) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if banner, ok := probePort(ctx, ip, d.port); ok {
				mu.Lock()
				open = append(open, openPort{def: d, banner: banner})
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool { return open[i].def.port < open[j].def.port })
	return buildFindings(open), nil
}

// probePort attempts a TCP connection and, on success, reads any banner the
// service volunteers within a short window.
func probePort(ctx context.Context, ip string, port int) (string, bool) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(bannerTimeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	return sanitizeBanner(buf[:n]), true
}

func sanitizeBanner(b []byte) string {
	line := b
	if i := indexOf(b, '\n'); i >= 0 {
		line = b[:i]
	}
	var sb strings.Builder
	for _, c := range line {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		}
	}
	s := strings.TrimSpace(sb.String())
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func indexOf(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func buildFindings(open []openPort) []scan.Finding {
	if len(open) == 0 {
		return []scan.Finding{{
			ID: "surface.ports", Category: scan.CategorySurface,
			Title: "No common ports exposed", Status: scan.StatusPass, Severity: scan.SeverityInfo,
			MaxPoints: 10, Points: 10,
			Detail: "None of the scanned common service ports accepted a connection — a tight network surface.",
		}}
	}

	// Informational inventory of everything found, plus a risk bucket. Open
	// ports are normal — SSH/HTTP/SMTP on a public server are expected. Only
	// High/Critical services (databases, admin panels, cleartext protocols)
	// warrant a failing grade; Low/Medium exposures are advisory.
	var inv, notable []string
	var serious []openPort
	worst := scan.SeverityInfo
	for _, o := range open {
		label := fmt.Sprintf("%d/%s", o.def.port, o.def.service)
		if o.banner != "" {
			label += " (" + o.banner + ")"
		}
		inv = append(inv, label)
		switch severityRank(o.def.severity) {
		case severityRank(scan.SeverityCritical), severityRank(scan.SeverityHigh):
			serious = append(serious, o)
			if severityRank(o.def.severity) < severityRank(worst) {
				worst = o.def.severity
			}
		case severityRank(scan.SeverityMedium), severityRank(scan.SeverityLow):
			notable = append(notable, fmt.Sprintf("%d/%s", o.def.port, o.def.service))
		}
	}

	findings := []scan.Finding{{
		ID: "surface.ports", Category: scan.CategorySurface,
		Title: "Open ports", Status: scan.StatusInfo, Severity: scan.SeverityInfo,
		Detail:   fmt.Sprintf("%d common port(s) accepted connections.", len(open)),
		Evidence: strings.Join(inv, ", "),
	}}

	exposed := scan.Finding{
		ID: "surface.exposed-services", Category: scan.CategorySurface,
		Title: "No dangerous services publicly exposed", MaxPoints: 20,
		Reference: "https://owasp.org/www-project-top-ten/",
	}
	switch {
	case len(serious) > 0:
		var parts []string
		for _, o := range serious {
			parts = append(parts, fmt.Sprintf("%d/%s — %s", o.def.port, o.def.service, o.def.why))
		}
		exposed.Title = "Dangerous services publicly exposed"
		exposed.Status, exposed.Severity, exposed.Points = scan.StatusFail, worst, 0
		exposed.Detail = "Sensitive services are reachable from the public internet."
		exposed.Evidence = strings.Join(parts, " · ")
		exposed.Fix = "Firewall these ports to trusted networks/VPN only; never expose databases or admin panels publicly."
	case len(notable) > 0:
		// Only routine admin/mail ports (e.g. SSH) — full marks, advisory note.
		exposed.Status, exposed.Severity, exposed.Points = scan.StatusPass, scan.SeverityInfo, 20
		exposed.Detail = "No databases or admin panels are exposed. Routine services are reachable — keep them hardened and patched."
		exposed.Evidence = "Exposed: " + strings.Join(notable, ", ")
	default:
		exposed.Status, exposed.Severity, exposed.Points = scan.StatusPass, scan.SeverityInfo, 20
		exposed.Detail = "No databases, admin interfaces, or cleartext services were reachable."
	}
	findings = append(findings, exposed)
	return findings
}

func severityRank(s scan.Severity) int {
	switch s {
	case scan.SeverityCritical:
		return 0
	case scan.SeverityHigh:
		return 1
	case scan.SeverityMedium:
		return 2
	case scan.SeverityLow:
		return 3
	default:
		return 4
	}
}
