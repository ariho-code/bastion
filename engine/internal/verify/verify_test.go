package verify

import (
	"strings"
	"testing"
)

func TestTokenDeterministicAndScoped(t *testing.T) {
	secret := "s3cret"
	a1 := Token(secret, "example.com")
	a2 := Token(secret, "EXAMPLE.COM.") // case + trailing dot normalized
	if a1 != a2 {
		t.Errorf("token should be normalized: %q != %q", a1, a2)
	}
	if len(a1) != 32 {
		t.Errorf("token length = %d, want 32", len(a1))
	}
	if Token(secret, "other.com") == a1 {
		t.Error("different domains must produce different tokens")
	}
	if Token("different", "example.com") == a1 {
		t.Error("different secrets must produce different tokens")
	}
}

func TestRecordFormat(t *testing.T) {
	rec := Record("s", "example.com")
	if !strings.HasPrefix(rec, RecordName+"=") {
		t.Errorf("record %q must start with %q=", rec, RecordName)
	}
}
