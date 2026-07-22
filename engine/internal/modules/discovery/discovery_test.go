package discovery

import (
	"testing"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

// findProbe returns the confirm func for a given path, for targeted testing.
func findProbe(t *testing.T, path string) func(r resp) bool {
	t.Helper()
	for _, p := range probes {
		if p.path == path {
			return p.confirm
		}
	}
	t.Fatalf("probe %q not found", path)
	return nil
}

func TestProtectedOrBody(t *testing.T) {
	confirm := findProbe(t, "admin")
	cases := []struct {
		name string
		r    resp
		want bool
	}{
		{"403 protected -> present", resp{status: 403}, true},
		{"401 protected -> present", resp{status: 401}, true},
		{"200 login page -> present", resp{status: 200, body: "<form>Please Sign In with your Password</form>"}, true},
		{"200 unrelated page -> absent", resp{status: 200, body: "<h1>Welcome to our blog</h1>"}, false},
		{"404 -> absent", resp{status: 404, body: "not found"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := confirm(c.r); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestBackupArchiveConfirm(t *testing.T) {
	confirm := findProbe(t, "backup.zip")
	if !confirm(resp{status: 200, body: "PK\x03\x04...zipdata", ct: "application/zip"}) {
		t.Error("real zip should confirm")
	}
	if confirm(resp{status: 200, body: "<!doctype html><html>soft 404</html>", ct: "text/html"}) {
		t.Error("HTML soft-404 must not confirm a backup archive")
	}
	if confirm(resp{status: 404, body: "PK"}) {
		t.Error("404 must not confirm")
	}
}

func TestSQLDumpConfirm(t *testing.T) {
	confirm := findProbe(t, "dump.sql")
	if !confirm(resp{status: 200, body: "-- MySQL dump\nINSERT INTO users VALUES(1);", ct: "application/octet-stream"}) {
		t.Error("sql dump should confirm")
	}
	if confirm(resp{status: 200, body: "INSERT INTO", ct: "text/html"}) {
		t.Error("HTML content must not confirm a sql dump")
	}
}

func TestBuildFindingsSeverityAndOrder(t *testing.T) {
	byGroup := map[group][]string{
		groupAPI:    {"Swagger UI"},
		groupBackup: {"backup.zip archive"},
		groupAdmin:  {"admin panel"},
	}
	out := buildFindings(byGroup, false)
	if len(out) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(out))
	}
	// groupMeta order puts backup (fail/high) first.
	if out[0].Severity != scan.SeverityHigh || out[0].Status != scan.StatusFail {
		t.Errorf("first finding should be backup fail/high, got %s/%s", out[0].Status, out[0].Severity)
	}
}

func TestBuildFindingsClean(t *testing.T) {
	out := buildFindings(map[group][]string{}, true)
	if len(out) != 1 || out[0].Status != scan.StatusPass {
		t.Fatalf("clean result should be a single pass finding, got %+v", out)
	}
	if out[0].MaxPoints == 0 {
		t.Error("clean pass should award points so the category scores")
	}
}
