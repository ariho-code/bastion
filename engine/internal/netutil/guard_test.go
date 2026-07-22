package netutil

import (
	"context"
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"127.0.0.1", false},       // loopback
		{"10.0.0.1", false},        // private
		{"192.168.1.1", false},     // private
		{"172.16.5.4", false},      // private
		{"169.254.169.254", false}, // link-local (cloud metadata)
		{"100.64.0.1", false},      // CGNAT
		{"::1", false},             // IPv6 loopback
		{"2606:4700:4700::1111", true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isPublicIP(ip); got != c.public {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.public)
		}
	}
}

func TestGuardBlocksInternal(t *testing.T) {
	g := NewGuard(false)
	ctx := context.Background()
	for _, host := range []string{"localhost", "127.0.0.1", "10.0.0.1", "foo.internal", "192.168.0.5"} {
		if err := g.Check(ctx, host); err == nil {
			t.Errorf("Check(%q) should have been blocked", host)
		}
	}
}

func TestGuardAllowPrivateEscapeHatch(t *testing.T) {
	g := NewGuard(true) // dev mode
	if err := g.Check(context.Background(), "127.0.0.1"); err != nil {
		t.Errorf("AllowPrivate should permit loopback, got %v", err)
	}
}
