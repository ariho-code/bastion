// Package auth provides tiered API-key authentication for the engine. Keys map
// to tiers, and tiers carry their own rate limits — the foundation for turning
// the scanner into a real, monetizable, abuse-resistant API.
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// Tier is an API plan. Higher tiers get higher rate limits (see RateLimit).
type Tier string

const (
	TierAnonymous Tier = "anonymous"
	TierFree      Tier = "free"
	TierPro       Tier = "pro"
	TierAgency    Tier = "agency"
)

// Identity is the authenticated principal attached to a request.
type Identity struct {
	Tier Tier
	// KeyID is a short, non-secret prefix of the API key for logging/attribution.
	KeyID string
	// Tenant is the owning tenant/organization id, when multi-tenant. Empty for
	// anonymous or single-tenant deployments.
	Tenant string
}

// Authenticator validates API keys in constant time and decides whether
// anonymous access is allowed.
type Authenticator struct {
	keys    map[string]Tier // full key -> tier
	require bool
}

// New builds an Authenticator from a key->tier map. If require is true,
// requests without a valid key are rejected on protected routes.
func New(keys map[string]string, require bool) *Authenticator {
	m := make(map[string]Tier, len(keys))
	for k, t := range keys {
		m[k] = normalizeTier(t)
	}
	return &Authenticator{keys: m, require: require}
}

// RequireKey reports whether protected routes must be authenticated.
func (a *Authenticator) RequireKey() bool { return a.require }

// Authenticate resolves the identity for a request. It returns the identity and
// whether a *valid* key was presented. An anonymous identity is returned when
// no key (or an unknown key) is supplied.
func (a *Authenticator) Authenticate(r *http.Request) (Identity, bool) {
	key := extractKey(r)
	if key == "" {
		return Identity{Tier: TierAnonymous}, false
	}
	// Constant-time comparison against each configured key to avoid leaking
	// which prefix matched via timing.
	var matchedTier Tier
	var matched bool
	for candidate, tier := range a.keys {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(key)) == 1 {
			matchedTier, matched = tier, true
		}
	}
	if !matched {
		return Identity{Tier: TierAnonymous}, false
	}
	return Identity{Tier: matchedTier, KeyID: keyID(key)}, true
}

func extractKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if after, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(after)
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// keyID returns a short, safe-to-log identifier for a key (never the secret).
func keyID(key string) string {
	if len(key) <= 10 {
		return "key_" + strings.Repeat("*", len(key))
	}
	return key[:10] + "…"
}

func normalizeTier(t string) Tier {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "agency":
		return TierAgency
	case "pro":
		return TierPro
	case "free":
		return TierFree
	default:
		return TierFree
	}
}
