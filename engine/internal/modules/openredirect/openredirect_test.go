package openredirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func verifiedTarget(t *testing.T, raw string) *scan.Target {
	t.Helper()
	tgt, err := scan.NewTarget(raw)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	tgt.Verified = true
	off := false
	tgt.Scope = scan.Scope{Stealth: &off, RequestDelayMs: 1} // fast, deterministic
	return tgt
}

// TestOpenRedirectDetectedOnVulnerableTarget: the fixture reflects any redirect
// parameter straight into a 302 Location — a textbook open redirect. The module
// must flag it.
func TestOpenRedirectDetectedOnVulnerableTarget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for _, p := range redirectParams {
			if v := r.URL.Query().Get(p); v != "" {
				w.Header().Set("Location", v) // vulnerable: unvalidated redirect
				w.WriteHeader(http.StatusFound)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := &Module{}
	findings, err := m.Run(context.Background(), verifiedTarget(t, srv.URL), scan.DefaultEnv())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByID(findings, "active.openredirect")
	if f == nil {
		t.Fatal("no openredirect finding produced")
	}
	if f.Status != scan.StatusFail {
		t.Errorf("vulnerable target should FAIL, got %s (%s) evidence=%q", f.Status, f.Severity, f.Evidence)
	}
	if f.Evidence == "" {
		t.Error("a detected open redirect must include evidence")
	}
}

// TestOpenRedirectSafeTarget: a fixture that ignores redirect parameters must
// NOT be flagged — the precision (no-false-positive) half of the guarantee.
func TestOpenRedirectSafeTarget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Safe: only ever redirects to a fixed internal path, never user input.
		if r.URL.Query().Get("next") != "" {
			w.Header().Set("Location", "/dashboard")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>home</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := &Module{}
	findings, err := m.Run(context.Background(), verifiedTarget(t, srv.URL), scan.DefaultEnv())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	f := findingByID(findings, "active.openredirect")
	if f == nil {
		t.Fatal("no openredirect finding produced")
	}
	if f.Status != scan.StatusPass {
		t.Errorf("safe target must PASS, got %s evidence=%q", f.Status, f.Evidence)
	}
}

func findingByID(fs []scan.Finding, id string) *scan.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}
