package activekit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// fastScope returns a scope tuned for tests: stealth off, minimal delay, so the
// pacer does not slow the suite while still exercising the real code paths.
func fastScope(maxReq int, exclude ...string) scan.Scope {
	off := false
	return scan.Scope{
		Stealth:        &off,
		RequestDelayMs: 1,
		MaxRequests:    maxReq,
		ExcludePaths:   exclude,
	}
}

func newClient(t *testing.T, base string, scope scan.Scope) *Client {
	t.Helper()
	tgt, err := scan.NewTarget(base)
	if err != nil {
		t.Fatalf("NewTarget(%q): %v", base, err)
	}
	tgt.Verified = true
	tgt.Scope = scope
	return NewClient(scan.DefaultEnv(), tgt)
}

// A deliberately-vulnerable fixture: reflects the `q` parameter unencoded at
// /search (reflected XSS), HTML-encodes it at /safe, and echoes auth headers.
func vulnFixture() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Results for " + q + "</body></html>"))
	})
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		enc := strings.ReplaceAll(q, "<", "&lt;")
		enc = strings.ReplaceAll(enc, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Safe: " + enc + "</body></html>"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin area"))
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("auth=" + r.Header.Get("Authorization")))
	})
	return httptest.NewServer(mux)
}

// TestReflectionDetection proves the core high-precision XSS primitive works
// end-to-end against a real server: a reflected canary is detected, and the
// same payload HTML-encoded is NOT falsely claimed as a vulnerability.
func TestReflectionDetection(t *testing.T) {
	srv := vulnFixture()
	defer srv.Close()
	c := newClient(t, srv.URL, fastScope(50))

	canary := Canary("bxss")
	payload := "<" + canary + ">"

	vuln := c.DoGET(context.Background(), srv.URL+"/search", map[string]string{"q": payload})
	if vuln.Err != nil {
		t.Fatalf("probe error: %v", vuln.Err)
	}
	if !ContainsUnencoded(vuln.Body, payload) {
		t.Errorf("reflected payload should be detected, body=%q", vuln.Body)
	}

	safe := c.DoGET(context.Background(), srv.URL+"/safe", map[string]string{"q": payload})
	if ContainsUnencoded(safe.Body, payload) {
		t.Errorf("HTML-encoded reflection must NOT be flagged, body=%q", safe.Body)
	}
}

// TestScopeEnforcement proves an excluded path is refused before any request.
func TestScopeEnforcement(t *testing.T) {
	srv := vulnFixture()
	defer srv.Close()
	c := newClient(t, srv.URL, fastScope(50, "/admin"))

	res := c.DoGET(context.Background(), srv.URL+"/admin", nil)
	if res.Err != errOutOfScope {
		t.Errorf("excluded path should be out of scope, got err=%v status=%d", res.Err, res.Status)
	}
	// An in-scope path still works.
	ok := c.DoGET(context.Background(), srv.URL+"/search", map[string]string{"q": "x"})
	if ok.Err != nil {
		t.Errorf("in-scope path should succeed, got %v", ok.Err)
	}
}

// TestBudgetEnforcement proves the request budget hard-caps active probing so a
// misconfigured module can never flood a target.
func TestBudgetEnforcement(t *testing.T) {
	srv := vulnFixture()
	defer srv.Close()
	c := newClient(t, srv.URL, fastScope(3))

	ok := 0
	var budgetHit bool
	for i := 0; i < 10; i++ {
		res := c.DoGET(context.Background(), srv.URL+"/search", map[string]string{"q": "x"})
		if res.Err == errBudget {
			budgetHit = true
			break
		}
		if res.Err == nil {
			ok++
		}
	}
	if !budgetHit {
		t.Error("budget should have been exhausted")
	}
	if ok > 3 {
		t.Errorf("budget allowed %d requests, cap was 3", ok)
	}
}

// TestSessionHeadersApplied proves owner-supplied authenticated context reaches
// probes (so verified owners can scan behind their own login).
func TestSessionHeadersApplied(t *testing.T) {
	srv := vulnFixture()
	defer srv.Close()
	tgt, _ := scan.NewTarget(srv.URL)
	tgt.Verified = true
	tgt.Scope = fastScope(50)
	env := scan.DefaultEnv()
	env.SessionHeaders = http.Header{"Authorization": {"Bearer owner-token-xyz"}}
	c := NewClient(env, tgt)

	res := c.DoGET(context.Background(), srv.URL+"/whoami", nil)
	if res.Err != nil {
		t.Fatalf("probe error: %v", res.Err)
	}
	if !strings.Contains(res.Body, "Bearer owner-token-xyz") {
		t.Errorf("session Authorization header not applied, body=%q", res.Body)
	}
}

// TestDiscoverExtractsSurface proves parameter/form discovery works against a
// real page — the input to every active module.
func TestDiscoverExtractsSurface(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<form action="/login" method="post">
				<input name="username" type="text">
				<input name="password" type="password">
			</form>
			<a href="/search?q=hello">search</a>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tgt, _ := scan.NewTarget(srv.URL)
	tgt.Verified = true
	surface := Discover(context.Background(), tgt, scan.DefaultEnv())

	var login *Form
	for i := range surface.Forms {
		if strings.Contains(surface.Forms[i].Action, "/login") {
			login = &surface.Forms[i]
		}
	}
	if login == nil {
		t.Fatalf("login form not discovered, surface=%+v", surface)
	}
	if !login.AuthLike {
		t.Error("form with a password field should be marked AuthLike")
	}
	if _, ok := login.Fields["username"]; !ok {
		t.Errorf("username field not discovered: %+v", login.Fields)
	}
}

// --- pure unit tests ---------------------------------------------------------

func TestContainsUnencoded(t *testing.T) {
	if !ContainsUnencoded("<b>hi xss123 there</b>", "xss123") {
		t.Error("literal marker should be detected")
	}
	if ContainsUnencoded("only &lt;script&gt; here", "<script>") {
		t.Error("entity-encoded-only marker must not be detected")
	}
	if ContainsUnencoded("", "x") || ContainsUnencoded("x", "") {
		t.Error("empty inputs must be false")
	}
}

func TestBudgetTake(t *testing.T) {
	b := &Budget{max: 2}
	if !b.Take() || !b.Take() {
		t.Fatal("first two takes should succeed")
	}
	if b.Take() {
		t.Error("third take should exceed the budget")
	}
	if b.Used() != 3 {
		t.Errorf("used = %d, want 3", b.Used())
	}
	var nilB *Budget
	if !nilB.Take() {
		t.Error("nil budget should allow (unbounded)")
	}
}

func TestCanaryUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c := Canary("bxss")
		if !strings.HasPrefix(c, "bxss") {
			t.Fatalf("canary missing prefix: %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate canary: %q", c)
		}
		seen[c] = true
	}
}
