package jwtcheck

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestInspectJWTAlgNone(t *testing.T) {
	hdr, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]string{"sub": "1"})
	tok := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."
	if inspectJWT(tok) == "" {
		t.Fatal("alg=none must be flagged")
	}
}

func TestInspectJWTOK(t *testing.T) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]string{"sub": "1"})
	tok := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"
	if inspectJWT(tok) != "" {
		t.Fatal("RS256 with signature must pass hygiene check")
	}
}
