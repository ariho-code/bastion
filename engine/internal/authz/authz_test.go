package authz

import "testing"

func TestRoleCan(t *testing.T) {
	cases := []struct {
		role Role
		perm Permission
		want bool
	}{
		{RoleAnonymous, PermScanRun, true},
		{RoleAnonymous, PermAuditRead, false},
		{RoleViewer, PermScanRun, false},
		{RoleViewer, PermModulesRead, true},
		{RoleScanner, PermScanActive, true},
		{RoleScanner, PermAuditRead, false},
		{RoleAdmin, PermAuditRead, true},
		{RoleAdmin, PermScanRun, true},
		{Role("bogus"), PermScanRun, false},
	}
	for _, c := range cases {
		if got := c.role.Can(c.perm); got != c.want {
			t.Errorf("%s.Can(%s) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}

func TestAuthorizeRBACGate(t *testing.T) {
	d := Authorize(AccessRequest{
		Subject: Subject{Role: RoleAnonymous},
		Action:  PermAuditRead,
		Resource: Resource{Type: "audit"},
	})
	if d.Allow {
		t.Error("anonymous must not read the audit trail")
	}
	d2 := Authorize(AccessRequest{
		Subject: Subject{Role: RoleAdmin},
		Action:  PermAuditRead,
		Resource: Resource{Type: "audit"},
	})
	if !d2.Allow {
		t.Errorf("admin should read the audit trail: %s", d2.Reason)
	}
}

func TestTenantIsolation(t *testing.T) {
	// Same tenant: allowed.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleScanner, Tenant: "acme"},
		Action:   PermScanRun,
		Resource: Resource{Type: "scan", Tenant: "acme"},
	}); !d.Allow {
		t.Errorf("same-tenant scan should be allowed: %s", d.Reason)
	}
	// Cross tenant: denied.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleScanner, Tenant: "acme"},
		Action:   PermScanRun,
		Resource: Resource{Type: "scan", Tenant: "globex"},
	}); d.Allow {
		t.Error("cross-tenant scan must be denied")
	}
	// Admin crosses tenants only within RBAC — tenantIsolation still blocks a
	// non-matching tenant unless admin of that tenant; here tenants differ.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleAdmin, Tenant: "acme"},
		Action:   PermScanRun,
		Resource: Resource{Type: "scan", Tenant: "globex"},
	}); d.Allow {
		t.Error("admin of acme must not act on globex resources")
	}
	// Single-tenant (no tenant on subject/resource): allowed.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleScanner},
		Action:   PermScanRun,
		Resource: Resource{Type: "scan"},
	}); !d.Allow {
		t.Errorf("single-tenant scan should be allowed: %s", d.Reason)
	}
}

func TestActiveScanOwnership(t *testing.T) {
	// Unverified active scan by a scanner: denied.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleScanner},
		Action:   PermScanActive,
		Resource: Resource{Type: "scan", Verified: false},
	}); d.Allow {
		t.Error("unverified active scan must be denied")
	}
	// Verified active scan: allowed.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleScanner},
		Action:   PermScanActive,
		Resource: Resource{Type: "scan", Verified: true},
	}); !d.Allow {
		t.Errorf("verified active scan should be allowed: %s", d.Reason)
	}
	// Admin may run active scans without per-target verification.
	if d := Authorize(AccessRequest{
		Subject:  Subject{Role: RoleAdmin},
		Action:   PermScanActive,
		Resource: Resource{Type: "scan", Verified: false},
	}); !d.Allow {
		t.Errorf("admin active scan should be allowed: %s", d.Reason)
	}
}
