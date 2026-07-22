package cors

import (
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

const look = "https://example.com.cors-probe.bastionscan.com"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name             string
		arb, null, lookO outcome
		status           scan.Status
		sev              scan.Severity
	}{
		{
			name:   "reflects arbitrary origin with credentials -> critical",
			arb:    outcome{acao: arbitraryOrigin, creds: true},
			status: scan.StatusFail, sev: scan.SeverityCritical,
		},
		{
			name:   "trusts null with credentials -> high",
			null:   outcome{acao: "null", creds: true},
			status: scan.StatusFail, sev: scan.SeverityHigh,
		},
		{
			name:   "look-alike prefix match with credentials -> high",
			lookO:  outcome{acao: look, creds: true},
			status: scan.StatusFail, sev: scan.SeverityHigh,
		},
		{
			name:   "reflects arbitrary origin, no credentials -> medium warn",
			arb:    outcome{acao: arbitraryOrigin, creds: false},
			status: scan.StatusWarn, sev: scan.SeverityMedium,
		},
		{
			name:   "trusts null, no credentials -> medium warn",
			null:   outcome{acao: "null", creds: false},
			status: scan.StatusWarn, sev: scan.SeverityMedium,
		},
		{
			name:   "wildcard without credentials -> pass (public API)",
			arb:    outcome{acao: "*"},
			status: scan.StatusPass, sev: scan.SeverityInfo,
		},
		{
			name:   "specific allow-list only -> pass",
			arb:    outcome{acao: "https://trusted.example", creds: true},
			status: scan.StatusPass, sev: scan.SeverityInfo,
		},
		{
			name:   "no CORS headers -> pass",
			status: scan.StatusPass, sev: scan.SeverityInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := evaluate(arbitraryOrigin, look, tt.arb, tt.null, tt.lookO)
			if f.Status != tt.status || f.Severity != tt.sev {
				t.Errorf("got %s/%s, want %s/%s", f.Status, f.Severity, tt.status, tt.sev)
			}
		})
	}
}

// A credentialed arbitrary reflection must outrank a wildcard also being present.
func TestEvaluatePrecedence(t *testing.T) {
	f := evaluate(arbitraryOrigin, look,
		outcome{acao: arbitraryOrigin, creds: true},
		outcome{acao: "null", creds: true},
		outcome{acao: look, creds: true},
	)
	if f.Severity != scan.SeverityCritical {
		t.Errorf("critical reflection should win precedence, got %s", f.Severity)
	}
}
