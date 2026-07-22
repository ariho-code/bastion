package abuse

import (
	"testing"
	"time"

	"github.com/ariho-code/bastionscan/engine/internal/scan"
)

func mustTarget(t *testing.T, raw string) *scan.Target {
	t.Helper()
	tg, err := scan.NewTarget(raw)
	if err != nil {
		t.Fatalf("NewTarget(%q): %v", raw, err)
	}
	return tg
}

func TestValidate(t *testing.T) {
	if err := Validate(mustTarget(t, "example.com")); err != nil {
		t.Errorf("plain host should be valid: %v", err)
	}
	if err := Validate(mustTarget(t, "https://user:pass@example.com")); err == nil {
		t.Error("embedded credentials should be rejected")
	}
	if err := Validate(mustTarget(t, "example.com:22")); err == nil {
		t.Error("non-web port 22 should be rejected")
	}
	if err := Validate(mustTarget(t, "example.com:8443")); err != nil {
		t.Errorf("web-alt port 8443 should be allowed: %v", err)
	}
}

func TestCooldown(t *testing.T) {
	c := NewCooldown(50 * time.Millisecond)

	if ok, _ := c.Check("example.com"); !ok {
		t.Fatal("first scan should be allowed")
	}
	if ok, retry := c.Check("example.com"); ok || retry < 1 {
		t.Errorf("immediate rescan should be blocked with retryAfter>=1, got ok=%v retry=%d", ok, retry)
	}
	// A different host is independent.
	if ok, _ := c.Check("other.com"); !ok {
		t.Error("different host should be allowed")
	}
	// After the window, the same host is allowed again.
	time.Sleep(60 * time.Millisecond)
	if ok, _ := c.Check("example.com"); !ok {
		t.Error("scan should be allowed after the cooldown window")
	}
}

func TestCooldownDisabled(t *testing.T) {
	c := NewCooldown(0)
	for i := 0; i < 3; i++ {
		if ok, _ := c.Check("example.com"); !ok {
			t.Fatal("cooldown of 0 should never block")
		}
	}
}
