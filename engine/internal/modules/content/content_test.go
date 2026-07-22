package content

import (
	"strings"
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func TestMixedContent(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		https  bool
		status scan.Status
		sev    scan.Severity
	}{
		{"clean https", `<script src="https://cdn.example.com/a.js"></script>`, true, scan.StatusPass, scan.SeverityInfo},
		{"active http script", `<script src="http://evil.example/a.js"></script>`, true, scan.StatusFail, scan.SeverityHigh},
		{"active http iframe", `<iframe src="http://ads.example/frame"></iframe>`, true, scan.StatusFail, scan.SeverityHigh},
		{"passive http image only", `<img src="http://img.example/pic.png">`, true, scan.StatusWarn, scan.SeverityMedium},
		{"http page is n/a", `<script src="http://x/a.js"></script>`, false, scan.StatusInfo, scan.SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mixedContentFinding(tt.body, tt.https)
			if f.Status != tt.status || f.Severity != tt.sev {
				t.Errorf("got status=%s sev=%s, want status=%s sev=%s", f.Status, f.Severity, tt.status, tt.sev)
			}
		})
	}
}

func TestSRI(t *testing.T) {
	host := "example.com"
	// Third-party script without integrity → warn.
	f := sriFinding(`<script src="https://cdn.jsdelivr.net/npm/x.js"></script>`, host)
	if f.Status != scan.StatusWarn {
		t.Errorf("cross-origin script w/o SRI: got %s, want warn", f.Status)
	}
	// Third-party script WITH integrity → pass.
	f = sriFinding(`<script src="https://cdn.jsdelivr.net/npm/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>`, host)
	if f.Status != scan.StatusPass {
		t.Errorf("cross-origin script w/ SRI: got %s, want pass", f.Status)
	}
	// Same-origin script needs no SRI → pass.
	f = sriFinding(`<script src="https://example.com/app.js"></script>`, host)
	if f.Status != scan.StatusPass {
		t.Errorf("same-origin script: got %s, want pass", f.Status)
	}
	// Relative script → same origin → pass.
	f = sriFinding(`<script src="/app.js"></script>`, host)
	if f.Status != scan.StatusPass {
		t.Errorf("relative script: got %s, want pass", f.Status)
	}
	// Cross-origin stylesheet without integrity → warn.
	f = sriFinding(`<link rel="stylesheet" href="https://fonts.evil.net/x.css">`, host)
	if f.Status != scan.StatusWarn {
		t.Errorf("cross-origin stylesheet w/o SRI: got %s, want warn", f.Status)
	}
}

func TestInsecureForm(t *testing.T) {
	f := formFinding(`<form action="http://insecure.example/login" method="post">`, true)
	if f.Status != scan.StatusFail || f.Severity != scan.SeverityHigh {
		t.Errorf("http form action on https: got %s/%s, want fail/high", f.Status, f.Severity)
	}
	f = formFinding(`<form action="https://secure.example/login">`, true)
	if f.Status != scan.StatusPass {
		t.Errorf("https form action: got %s, want pass", f.Status)
	}
	f = formFinding(`<form action="/login">`, true)
	if f.Status != scan.StatusPass {
		t.Errorf("relative form action: got %s, want pass", f.Status)
	}
}

func TestTabnabbing(t *testing.T) {
	f := tabnabbingFinding(`<a href="https://other.example" target="_blank">out</a>`)
	if f.Status != scan.StatusWarn {
		t.Errorf("unsafe _blank: got %s, want warn", f.Status)
	}
	f = tabnabbingFinding(`<a href="https://other.example" target="_blank" rel="noopener">out</a>`)
	if f.Status != scan.StatusPass {
		t.Errorf("safe _blank: got %s, want pass", f.Status)
	}
	// _blank to a relative (same-site) link isn't the classic risk vector.
	f = tabnabbingFinding(`<a href="/page" target="_blank">in</a>`)
	if f.Status != scan.StatusPass {
		t.Errorf("relative _blank: got %s, want pass", f.Status)
	}
}

func TestDedupeCap(t *testing.T) {
	got := dedupeCap([]string{"a", "a", "b", "c", "d", "e"}, 3)
	if len(got) != 4 { // 3 items + a "…+N more" marker
		t.Fatalf("dedupeCap len = %d (%v), want 4", len(got), got)
	}
	if !strings.Contains(got[3], "more") {
		t.Errorf("expected overflow marker, got %v", got)
	}
}
