package scan

import "testing"

func TestScopePathAllowed(t *testing.T) {
	s := Scope{ExcludePaths: []string{"/billing", "/admin/prod"}}
	if !s.PathAllowed("/api/users") {
		t.Error("api should be allowed")
	}
	if s.PathAllowed("/billing/invoice") {
		t.Error("billing should be excluded")
	}
	if s.PathAllowed("/admin/prod/keys") {
		t.Error("admin/prod should be excluded")
	}

	s2 := Scope{IncludePaths: []string{"/api/"}}
	if !s2.PathAllowed("/api/v1") {
		t.Error("include should allow /api/v1")
	}
	if s2.PathAllowed("/login") {
		t.Error("login outside include should be blocked")
	}
}

func TestScopeModuleAllowed(t *testing.T) {
	s := Scope{DisableModules: []string{"authweak"}}
	if s.ModuleAllowed("authweak") {
		t.Error("disabled module must not run")
	}
	if !s.ModuleAllowed("sqli") {
		t.Error("other modules still allowed")
	}

	s2 := Scope{EnableModules: []string{"sqli", "xss"}}
	if !s2.ModuleAllowed("sqli") {
		t.Error("allow-listed sqli")
	}
	if s2.ModuleAllowed("authweak") {
		t.Error("non-listed module blocked by allow-list")
	}
}

func TestScopeIsSafeDefault(t *testing.T) {
	if !DefaultScope().IsSafe() {
		t.Error("default scope must be safe mode")
	}
	f := false
	s := Scope{SafeMode: &f}
	if s.IsSafe() {
		t.Error("explicit false must disable safe mode")
	}
}
