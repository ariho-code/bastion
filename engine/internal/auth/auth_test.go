package auth

import (
	"net/http"
	"testing"
)

func req(headers map[string]string) *http.Request {
	r, _ := http.NewRequest("GET", "/v1/scan", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestAuthenticateValidKey(t *testing.T) {
	a := New(map[string]string{"bk_live_abc": "pro"}, true)

	id, ok := a.Authenticate(req(map[string]string{"Authorization": "Bearer bk_live_abc"}))
	if !ok || id.Tier != TierPro {
		t.Fatalf("expected valid pro identity, got tier=%q ok=%v", id.Tier, ok)
	}
	// KeyID must never be the raw secret.
	if id.KeyID == "bk_live_abc" {
		t.Error("KeyID leaked the raw key")
	}
}

func TestAuthenticateViaXAPIKeyHeader(t *testing.T) {
	a := New(map[string]string{"bk_live_xyz": "agency"}, true)
	id, ok := a.Authenticate(req(map[string]string{"X-API-Key": "bk_live_xyz"}))
	if !ok || id.Tier != TierAgency {
		t.Fatalf("X-API-Key auth failed: tier=%q ok=%v", id.Tier, ok)
	}
}

func TestAuthenticateUnknownKeyIsAnonymous(t *testing.T) {
	a := New(map[string]string{"bk_live_abc": "pro"}, true)
	id, ok := a.Authenticate(req(map[string]string{"Authorization": "Bearer wrong"}))
	if ok || id.Tier != TierAnonymous {
		t.Fatalf("unknown key should be anonymous, got tier=%q ok=%v", id.Tier, ok)
	}
}

func TestAuthenticateNoKey(t *testing.T) {
	a := New(map[string]string{}, false)
	id, ok := a.Authenticate(req(nil))
	if ok || id.Tier != TierAnonymous {
		t.Fatalf("no key should be anonymous, got tier=%q ok=%v", id.Tier, ok)
	}
}

func TestUnknownTierDefaultsToFree(t *testing.T) {
	a := New(map[string]string{"k": "platinum"}, true)
	id, _ := a.Authenticate(req(map[string]string{"X-API-Key": "k"}))
	if id.Tier != TierFree {
		t.Errorf("unknown tier should default to free, got %q", id.Tier)
	}
}

func TestRequireKey(t *testing.T) {
	if !New(nil, true).RequireKey() {
		t.Error("RequireKey should be true")
	}
	if New(nil, false).RequireKey() {
		t.Error("RequireKey should be false")
	}
}
