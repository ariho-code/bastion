package fingerprint

import (
	"strings"
	"testing"
)

func TestLibrariesFinding(t *testing.T) {
	body := `<html><head>
	<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/css/bootstrap.min.css">
	<script src="/assets/vendor/lodash.4.17.11.js"></script>
	</head><body></body></html>`
	f := librariesFinding(body)
	if f == nil {
		t.Fatal("expected a libraries finding")
	}
	for _, want := range []string{"jQuery 3.4.1", "Bootstrap 4.3.1", "Lodash 4.17.11"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence %q missing %q", f.Evidence, want)
		}
	}
}

func TestLibrariesFindingNoneFound(t *testing.T) {
	if f := librariesFinding(`<html><body>no libraries here</body></html>`); f != nil {
		t.Errorf("expected nil, got %+v", f)
	}
	if f := librariesFinding(""); f != nil {
		t.Error("empty body should yield nil")
	}
}
