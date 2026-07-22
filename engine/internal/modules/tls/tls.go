// Package tls implements a deep TLS/certificate analysis module. It actively
// negotiates handshakes across protocol versions and cipher suites to build an
// accurate picture of a server's transport security — the kind of inspection
// SSL Labs is known for, done non-destructively.
package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func init() { scan.Register(&Module{}) }

// Module performs deep TLS inspection. It runs from the Standard profile up.
type Module struct{}

func (m *Module) ID() string            { return "tls" }
func (m *Module) Category() scan.Category { return scan.CategoryTransport }
func (m *Module) MinLevel() int          { return scan.ProfileStandard.Level }
func (m *Module) Description() string {
	return "Deep TLS analysis: protocol & cipher enumeration, certificate chain, key strength, forward secrecy"
}

// Supports runs for any https-capable target. Plain-http-only URLs still get
// checked on 443 in case TLS is available.
func (m *Module) Supports(t *scan.Target) bool { return t.Host != "" }

const (
	dialTimeout      = 6 * time.Second
	handshakeTimeout = 6 * time.Second
	cipherWorkers    = 8
)

// versionsToTest is the set of protocol versions we probe individually.
var versionsToTest = []struct {
	name string
	id   uint16
}{
	{"TLS 1.3", tls.VersionTLS13},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.0", tls.VersionTLS10},
}

func (m *Module) Run(ctx context.Context, t *scan.Target, _ *scan.Env) ([]scan.Finding, error) {
	addr := net.JoinHostPort(t.Host, t.PortOr("443"))

	// Baseline handshake: negotiate the best the server offers so we can read
	// the presented certificate and the server's preferred cipher.
	base, err := handshake(ctx, addr, t.Host, tls.VersionTLS10, tls.VersionTLS13, nil)
	if err != nil {
		return []scan.Finding{{
			ID: "tls.handshake", Category: scan.CategoryTransport,
			Title: "TLS not available", Status: scan.StatusFail, Severity: scan.SeverityHigh,
			MaxPoints: 15, Points: 0,
			Detail:    fmt.Sprintf("Could not establish a TLS connection on %s: %v", addr, err),
			Fix:       "Serve the site over HTTPS with a valid certificate on port 443.",
			Reference: "https://developer.mozilla.org/docs/Web/Security/Transport_Layer_Security",
		}}, nil
	}

	var findings []scan.Finding
	findings = append(findings, m.protocolFindings(ctx, addr, t.Host)...)
	findings = append(findings, m.cipherFindings(ctx, addr, t.Host))
	findings = append(findings, forwardSecrecyFinding(base))
	findings = append(findings, certFindings(t.Host, base)...)
	return findings, nil
}

// protocolFindings probes each protocol version and grades modern vs. legacy.
func (m *Module) protocolFindings(ctx context.Context, addr, host string) []scan.Finding {
	supported := map[string]bool{}
	var order []string
	for _, v := range versionsToTest {
		_, err := handshake(ctx, addr, host, v.id, v.id, nil)
		supported[v.name] = err == nil
		if err == nil {
			order = append(order, v.name)
		}
	}

	modern := supported["TLS 1.2"] || supported["TLS 1.3"]
	legacy := supported["TLS 1.0"] || supported["TLS 1.1"]
	evidence := "Supported: " + strings.Join(order, ", ")
	if len(order) == 0 {
		evidence = "No standard TLS version negotiated"
	}

	out := []scan.Finding{{
		ID: "tls.version.modern", Category: scan.CategoryTransport,
		Title: "Modern TLS supported", MaxPoints: 15,
		Detail:   "TLS 1.2 or 1.3 must be available for secure connections.",
		Evidence: evidence,
	}}
	if modern {
		out[0].Status, out[0].Severity, out[0].Points = scan.StatusPass, scan.SeverityInfo, 15
	} else {
		out[0].Status, out[0].Severity, out[0].Points = scan.StatusFail, scan.SeverityCritical, 0
		out[0].Fix = "Enable TLS 1.2 and TLS 1.3 on your server."
	}

	legacyF := scan.Finding{
		ID: "tls.version.legacy", Category: scan.CategoryTransport,
		Title: "Legacy TLS disabled", MaxPoints: 15,
		Detail:    "TLS 1.0 and 1.1 are deprecated and vulnerable to downgrade and padding-oracle attacks.",
		Evidence:  evidence,
		Reference: "https://datatracker.ietf.org/doc/rfc8996/",
	}
	if legacy {
		legacyF.Status, legacyF.Severity, legacyF.Points = scan.StatusFail, scan.SeverityHigh, 0
		legacyF.Fix = "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer."
	} else {
		legacyF.Status, legacyF.Severity, legacyF.Points = scan.StatusPass, scan.SeverityInfo, 15
	}
	out = append(out, legacyF)

	tls13 := scan.Finding{
		ID: "tls.version.tls13", Category: scan.CategoryTransport,
		Title: "TLS 1.3 supported", MaxPoints: 5,
		Detail:   "TLS 1.3 removes legacy crypto and speeds up handshakes.",
		Evidence: evidence,
	}
	if supported["TLS 1.3"] {
		tls13.Status, tls13.Severity, tls13.Points = scan.StatusPass, scan.SeverityInfo, 5
	} else {
		tls13.Status, tls13.Severity, tls13.Points = scan.StatusWarn, scan.SeverityLow, 0
		tls13.Fix = "Enable TLS 1.3 for stronger, faster connections."
	}
	out = append(out, tls13)
	return out
}

// cipherFindings enumerates which TLS 1.2 cipher suites the server accepts and
// flags any known-weak ones. TLS 1.3 suites are fixed and always strong.
func (m *Module) cipherFindings(ctx context.Context, addr, host string) scan.Finding {
	type candidate struct {
		id       uint16
		name     string
		insecure bool
	}
	var candidates []candidate
	for _, cs := range tls.CipherSuites() {
		if supportsTLS12(cs.SupportedVersions) {
			candidates = append(candidates, candidate{cs.ID, cs.Name, false})
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if supportsTLS12(cs.SupportedVersions) {
			candidates = append(candidates, candidate{cs.ID, cs.Name, true})
		}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted []string
		weak     []string
		sem      = make(chan struct{}, cipherWorkers)
	)
	for _, c := range candidates {
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			st, err := handshake(ctx, addr, host, tls.VersionTLS12, tls.VersionTLS12, []uint16{c.id})
			if err != nil || st.CipherSuite != c.id {
				return
			}
			mu.Lock()
			accepted = append(accepted, c.name)
			if c.insecure || isWeakCipherName(c.name) {
				weak = append(weak, c.name)
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	f := scan.Finding{
		ID: "tls.ciphers", Category: scan.CategoryTransport,
		Title: "Strong cipher suites only", MaxPoints: 15,
		Reference: "https://ciphersuite.info/",
	}
	switch {
	case len(accepted) == 0:
		// Server likely negotiates only TLS 1.3 (or refuses forced 1.2 suites).
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 15
		f.Detail = "No weak TLS 1.2 cipher suites were accepted (server prefers TLS 1.3 or a hardened suite set)."
	case len(weak) == 0:
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 15
		f.Detail = fmt.Sprintf("All %d negotiable TLS 1.2 cipher suites are strong.", len(accepted))
		f.Evidence = strings.Join(accepted, ", ")
	default:
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
		f.Detail = fmt.Sprintf("%d weak cipher suite(s) accepted (CBC/3DES/RC4/SHA-1 or export-grade).", len(weak))
		f.Evidence = "Weak: " + strings.Join(weak, ", ")
		f.Fix = "Disable CBC-mode, 3DES, RC4 and SHA-1 cipher suites; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305)."
	}
	return f
}

func forwardSecrecyFinding(st *tls.ConnectionState) scan.Finding {
	name := tls.CipherSuiteName(st.CipherSuite)
	fs := st.Version == tls.VersionTLS13 ||
		strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE")
	f := scan.Finding{
		ID: "tls.forwardsecrecy", Category: scan.CategoryTransport,
		Title: "Forward secrecy", MaxPoints: 10,
		Evidence:  fmt.Sprintf("Negotiated %s via %s", name, versionName(st.Version)),
		Reference: "https://en.wikipedia.org/wiki/Forward_secrecy",
	}
	if fs {
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "The negotiated suite provides forward secrecy — past traffic stays safe if the key leaks."
	} else {
		f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityMedium, 0
		f.Detail = "The negotiated suite does not provide forward secrecy."
		f.Fix = "Prefer ECDHE/DHE key exchange so session keys aren't tied to the server's private key."
	}
	return f
}

// certFindings analyzes the presented leaf certificate: trust, expiry, key
// strength, signature algorithm, and hostname match.
func certFindings(host string, st *tls.ConnectionState) []scan.Finding {
	if len(st.PeerCertificates) == 0 {
		return []scan.Finding{{
			ID: "tls.cert", Category: scan.CategoryTransport,
			Title: "No certificate presented", Status: scan.StatusFail, Severity: scan.SeverityHigh,
			MaxPoints: 15, Detail: "The server completed a handshake without presenting a certificate.",
		}}
	}
	leaf := st.PeerCertificates[0]
	var out []scan.Finding

	// Trust: verify the chain against system roots.
	trust := scan.Finding{
		ID: "tls.cert.trust", Category: scan.CategoryTransport,
		Title: "Certificate trusted", MaxPoints: 15,
	}
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		trust.Status, trust.Severity, trust.Points = scan.StatusFail, scan.SeverityHigh, 0
		trust.Detail = "The certificate chain did not validate against trusted roots."
		trust.Evidence = err.Error()
		trust.Fix = "Install a certificate from a trusted CA and serve the full intermediate chain."
	} else {
		trust.Status, trust.Severity, trust.Points = scan.StatusPass, scan.SeverityInfo, 15
		trust.Detail = "The certificate chains to a trusted root and matches the hostname."
		trust.Evidence = "Issuer: " + leaf.Issuer.CommonName
	}
	out = append(out, trust)

	// Expiry.
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	exp := scan.Finding{
		ID: "tls.cert.expiry", Category: scan.CategoryTransport,
		Title: "Certificate validity", MaxPoints: 10,
		Evidence: fmt.Sprintf("Valid %s → %s (%d days left)",
			leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"), days),
	}
	switch {
	case days < 0:
		exp.Status, exp.Severity, exp.Points = scan.StatusFail, scan.SeverityCritical, 0
		exp.Detail = "The certificate has expired."
		exp.Fix = "Renew the certificate immediately and automate renewal."
	case days < 15:
		exp.Status, exp.Severity, exp.Points = scan.StatusFail, scan.SeverityHigh, 0
		exp.Detail = fmt.Sprintf("The certificate expires in %d days.", days)
		exp.Fix = "Renew now; automate renewal (e.g. ACME/Let's Encrypt)."
	case days < 30:
		exp.Status, exp.Severity, exp.Points = scan.StatusWarn, scan.SeverityLow, 6
		exp.Detail = fmt.Sprintf("The certificate expires in %d days.", days)
		exp.Fix = "Renew soon and automate renewal."
	default:
		exp.Status, exp.Severity, exp.Points = scan.StatusPass, scan.SeverityInfo, 10
		exp.Detail = "The certificate is valid and not near expiry."
	}
	out = append(out, exp)

	// Key strength.
	out = append(out, keyStrengthFinding(leaf))

	// Signature algorithm.
	sig := scan.Finding{
		ID: "tls.cert.signature", Category: scan.CategoryTransport,
		Title: "Certificate signature", MaxPoints: 5,
		Evidence: leaf.SignatureAlgorithm.String(),
	}
	if isWeakSignature(leaf.SignatureAlgorithm) {
		sig.Status, sig.Severity, sig.Points = scan.StatusFail, scan.SeverityHigh, 0
		sig.Detail = "The certificate uses a weak signature algorithm (MD5 or SHA-1)."
		sig.Fix = "Reissue the certificate with a SHA-256 (or stronger) signature."
	} else {
		sig.Status, sig.Severity, sig.Points = scan.StatusPass, scan.SeverityInfo, 5
		sig.Detail = "The certificate uses a modern signature algorithm."
	}
	out = append(out, sig)

	// Hostname match (independent of full-chain trust).
	hn := scan.Finding{
		ID: "tls.cert.hostname", Category: scan.CategoryTransport,
		Title: "Hostname matches certificate", MaxPoints: 5,
	}
	if err := leaf.VerifyHostname(host); err != nil {
		hn.Status, hn.Severity, hn.Points = scan.StatusFail, scan.SeverityHigh, 0
		hn.Detail = "The certificate is not valid for this hostname."
		hn.Evidence = err.Error()
		hn.Fix = "Issue a certificate whose SANs include this hostname."
	} else {
		hn.Status, hn.Severity, hn.Points = scan.StatusPass, scan.SeverityInfo, 5
		hn.Detail = "The hostname is covered by the certificate's SANs."
		if len(leaf.DNSNames) > 0 {
			hn.Evidence = "SANs: " + strings.Join(capSlice(leaf.DNSNames, 8), ", ")
		}
	}
	out = append(out, hn)
	return out
}

func keyStrengthFinding(leaf *x509.Certificate) scan.Finding {
	f := scan.Finding{
		ID: "tls.cert.key", Category: scan.CategoryTransport,
		Title: "Certificate key strength", MaxPoints: 10,
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		f.Evidence = fmt.Sprintf("RSA %d-bit", bits)
		if bits < 2048 {
			f.Status, f.Severity, f.Points = scan.StatusFail, scan.SeverityHigh, 0
			f.Detail = "RSA keys smaller than 2048 bits are considered weak."
			f.Fix = "Reissue with a 2048-bit (or larger) RSA key, or switch to ECDSA P-256."
		} else {
			f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
			f.Detail = "The certificate uses a strong RSA key."
		}
	case *ecdsa.PublicKey:
		bits := pub.Curve.Params().BitSize
		f.Evidence = fmt.Sprintf("ECDSA P-%d", bits)
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "The certificate uses a strong elliptic-curve key."
	case ed25519.PublicKey:
		f.Evidence = "Ed25519"
		f.Status, f.Severity, f.Points = scan.StatusPass, scan.SeverityInfo, 10
		f.Detail = "The certificate uses a modern Ed25519 key."
	default:
		f.Evidence = fmt.Sprintf("%T", leaf.PublicKey)
		f.Status, f.Severity, f.Points = scan.StatusWarn, scan.SeverityLow, 5
		f.Detail = "Unrecognized public key type."
	}
	return f
}

// handshake dials the address and performs a TLS handshake with the given
// version bounds and (optional) cipher restriction. Certificate verification is
// disabled here because this module performs its own, richer validation.
func handshake(ctx context.Context, addr, serverName string, minV, maxV uint16, ciphers []uint16) (*tls.ConnectionState, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         minV,
		MaxVersion:         maxV,
		InsecureSkipVerify: true, // module does its own chain validation
	}
	if ciphers != nil {
		cfg.CipherSuites = ciphers
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	st := tc.ConnectionState()
	return &st, nil
}

func supportsTLS12(vers []uint16) bool {
	for _, v := range vers {
		if v == tls.VersionTLS12 {
			return true
		}
	}
	return false
}

func isWeakCipherName(name string) bool {
	n := strings.ToUpper(name)
	for _, bad := range []string{"RC4", "3DES", "DES", "CBC", "NULL", "EXPORT", "MD5", "_SHA_", "_SHA "} {
		if strings.Contains(n, bad) {
			return true
		}
	}
	return strings.HasSuffix(n, "_SHA")
}

func isWeakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	}
	return false
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func capSlice(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}
