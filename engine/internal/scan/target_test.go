package scan

import "testing"

func TestNewTarget(t *testing.T) {
	cases := []struct {
		in         string
		wantHost   string
		wantDomain string
		wantErr    bool
	}{
		{"example.com", "example.com", "example.com", false},
		{"https://Www.Example.COM/path", "www.example.com", "example.com", false},
		{"http://sub.deep.example.co.uk", "sub.deep.example.co.uk", "example.co.uk", false},
		{"ftp://example.com", "", "", true},
		{"   ", "", "", true},
		{"not a url with spaces", "", "", true},
	}
	for _, c := range cases {
		tg, err := NewTarget(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NewTarget(%q) expected error, got none", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NewTarget(%q) unexpected error: %v", c.in, err)
			continue
		}
		if tg.Host != c.wantHost {
			t.Errorf("NewTarget(%q).Host = %q, want %q", c.in, tg.Host, c.wantHost)
		}
		if tg.Domain != c.wantDomain {
			t.Errorf("NewTarget(%q).Domain = %q, want %q", c.in, tg.Domain, c.wantDomain)
		}
	}
}

func TestParseProfile(t *testing.T) {
	if ParseProfile("deep").Level != ProfileDeep.Level {
		t.Error("deep should parse to ProfileDeep")
	}
	if ParseProfile("").Name != ProfileStandard.Name {
		t.Error("empty should default to standard")
	}
	if ParseProfile("nonsense").Name != ProfileStandard.Name {
		t.Error("unknown should default to standard")
	}
}
