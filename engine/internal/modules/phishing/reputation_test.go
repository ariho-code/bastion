package phishing

import (
	"testing"
	"time"
)

func TestParseRDAPRegistration(t *testing.T) {
	body := []byte(`{
		"objectClassName": "domain",
		"ldhName": "EXAMPLE.COM",
		"events": [
			{"eventAction": "last changed", "eventDate": "2024-08-01T00:00:00Z"},
			{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2025-08-13T04:00:00Z"}
		]
	}`)
	got, ok := parseRDAPRegistration(body)
	if !ok {
		t.Fatal("expected a registration date")
	}
	if got.Year() != 1995 || got.Month() != time.August || got.Day() != 14 {
		t.Errorf("parsed %v, want 1995-08-14", got)
	}
}

func TestParseRDAPRegistrationMissing(t *testing.T) {
	if _, ok := parseRDAPRegistration([]byte(`{"events":[{"eventAction":"expiration","eventDate":"2025-01-01T00:00:00Z"}]}`)); ok {
		t.Error("must not find a registration date when none is present")
	}
	if _, ok := parseRDAPRegistration([]byte(`not json`)); ok {
		t.Error("must fail gracefully on malformed JSON")
	}
}

func TestParseRDAPDateLayouts(t *testing.T) {
	for _, s := range []string{
		"2020-01-02T15:04:05Z",
		"2020-01-02T15:04:05.123Z",
		"2020-01-02T15:04:05",
		"2020-01-02 15:04:05",
		"2020-01-02",
	} {
		if _, ok := parseRDAPDate(s); !ok {
			t.Errorf("layout not parsed: %q", s)
		}
	}
	if _, ok := parseRDAPDate("14th August 1995"); ok {
		t.Error("free-form date should not parse")
	}
}

func TestAgeToSignal(t *testing.T) {
	cases := []struct {
		days      int
		wantOK    bool
		wantCode  string
		minWeight int
	}{
		{-1, false, "", 0},
		{2, true, "domain-new", 30},
		{20, true, "domain-new", 22},
		{75, true, "domain-young", 12},
		{400, false, "", 0},
	}
	for _, c := range cases {
		s, ok := ageToSignal(c.days)
		if ok != c.wantOK {
			t.Errorf("ageToSignal(%d) ok=%v, want %v", c.days, ok, c.wantOK)
			continue
		}
		if ok && (s.code != c.wantCode || s.weight < c.minWeight) {
			t.Errorf("ageToSignal(%d) = %+v, want code %q weight>=%d", c.days, s, c.wantCode, c.minWeight)
		}
	}
}

func TestBlocklistListed(t *testing.T) {
	cases := []struct {
		name    string
		answers []string
		want    bool
	}{
		{"spamhaus dbl phish", []string{"127.0.1.4"}, true},
		{"surbl listed", []string{"127.0.0.2"}, true},
		{"not listed nxdomain", nil, false},
		{"not listed 127.0.0.1", []string{"127.0.0.1"}, false},
		{"error code ignored", []string{"127.255.255.254"}, false},
		{"public ip ignored", []string{"93.184.216.34"}, false},
	}
	for _, c := range cases {
		if got := blocklistListed(c.answers); got != c.want {
			t.Errorf("%s: blocklistListed(%v) = %v, want %v", c.name, c.answers, got, c.want)
		}
	}
}

// Network signals must escalate the verdict through the same assess() pipeline.
func TestReputationOverrides(t *testing.T) {
	// Blocklist hit alone is conclusive.
	blk := signal{"blocklist", 40, "listed"}
	a := assess(mkInput("some-store.com", "some-store.com"), blk)
	if a.verdict != verdictDangerous {
		t.Errorf("blocklisted domain should be DANGEROUS, got %s", a.verdict.label())
	}

	// Fresh domain + brand impersonation is a textbook fresh phishing kit.
	fresh := signal{"domain-new", 30, "registered this week"}
	a2 := assess(mkInput("paypal-verify.xyz", "paypal-verify.xyz"), fresh)
	if a2.verdict != verdictDangerous {
		t.Errorf("fresh impersonating domain should be DANGEROUS, got %s (%d) %+v",
			a2.verdict.label(), a2.score, a2.signals)
	}

	// Fresh domain WITHOUT impersonation should not be forced to dangerous.
	a3 := assess(mkInput("mynewblog.com", "mynewblog.com"), fresh)
	if a3.verdict == verdictDangerous {
		t.Errorf("a fresh but otherwise-clean domain must not be DANGEROUS: %+v", a3.signals)
	}
}
