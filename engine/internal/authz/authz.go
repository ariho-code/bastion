// Package authz is the engine's authorization layer: a default-deny policy
// engine combining Role-Based Access Control (RBAC) with Attribute-Based Access
// Control (ABAC). RBAC answers "does this role hold this permission?"; ABAC then
// applies contextual constraints — tenant isolation, ownership gating — that a
// static role matrix cannot express. A request is allowed only if RBAC grants
// the permission AND every ABAC policy permits it.
package authz

// Permission is a fine-grained capability checked at an enforcement point.
type Permission string

const (
	PermScanRun     Permission = "scan:run"     // run a standard/deep scan
	PermScanActive  Permission = "scan:active"  // run intrusive active-tier modules
	PermModulesRead Permission = "modules:read" // list engine capabilities
	PermAuditRead   Permission = "audit:read"   // read the audit trail
	PermAdmin       Permission = "admin:*"      // administrative superpower
)

// Role is a named bundle of permissions assigned to a principal.
type Role string

const (
	RoleAnonymous Role = "anonymous" // unauthenticated public users
	RoleViewer    Role = "viewer"    // read-only
	RoleScanner   Role = "scanner"   // authenticated scanning users
	RoleAdmin     Role = "admin"     // tenant administrators
)

// rolePermissions is the RBAC matrix. Anonymous users keep the product's open
// scanning capability; only administrators can read the audit trail. RoleAdmin
// is expanded to every permission via Can().
var rolePermissions = map[Role]map[Permission]bool{
	RoleAnonymous: {PermScanRun: true, PermScanActive: true, PermModulesRead: true},
	RoleViewer:    {PermModulesRead: true},
	RoleScanner:   {PermScanRun: true, PermScanActive: true, PermModulesRead: true},
	RoleAdmin:     {PermScanRun: true, PermScanActive: true, PermModulesRead: true, PermAuditRead: true, PermAdmin: true},
}

// Can reports whether the role holds the permission (pure RBAC, no context).
func (r Role) Can(p Permission) bool {
	perms := rolePermissions[r]
	if perms == nil {
		return false
	}
	return perms[p] || perms[PermAdmin]
}

// Subject is the authenticated principal making a request.
type Subject struct {
	Role   Role
	Tier   string
	Tenant string // owning tenant/org, empty in single-tenant deployments
}

// Resource is the thing being acted upon and its relevant attributes.
type Resource struct {
	Type     string // "scan" | "audit" | ...
	Tenant   string // tenant that owns the resource, when applicable
	Domain   string // target domain, for scans
	Verified bool   // ownership-verified target (unlocks active scanning)
}

// AccessRequest bundles subject, action and resource for evaluation.
type AccessRequest struct {
	Subject  Subject
	Action   Permission
	Resource Resource
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allow  bool
	Reason string
}

func allow() Decision            { return Decision{Allow: true} }
func deny(reason string) Decision { return Decision{Allow: false, Reason: reason} }

// abacPolicy is one attribute-based rule. Returning a deny short-circuits.
type abacPolicy func(AccessRequest) Decision

// policies are evaluated in order after RBAC passes. Each is independent and
// default-allow (it only denies when its specific condition is violated), so the
// overall decision is allow-iff-RBAC-grants-AND-no-policy-denies.
var policies = []abacPolicy{
	tenantIsolation,
	activeScanOwnership,
}

// tenantIsolation forbids acting on another tenant's resource, unless the
// subject is an admin of the resource's tenant. Only enforced when both the
// subject and resource carry a tenant (multi-tenant deployments).
func tenantIsolation(req AccessRequest) Decision {
	rt := req.Resource.Tenant
	st := req.Subject.Tenant
	if rt == "" || st == "" {
		return allow() // single-tenant / not tenant-scoped
	}
	if st != rt {
		return deny("cross-tenant access is not permitted")
	}
	return allow()
}

// activeScanOwnership requires an active-tier scan to target an ownership-verified
// domain — a real authorization boundary between "analyze anything safely" and
// "aggressively probe assets". Admins are exempt (they operate their own estate).
func activeScanOwnership(req AccessRequest) Decision {
	if req.Action != PermScanActive {
		return allow()
	}
	if req.Subject.Role == RoleAdmin || req.Resource.Verified {
		return allow()
	}
	return deny("active-tier scanning requires a verified-owned target")
}

// Authorize returns the final decision: default-deny unless RBAC grants the
// permission and every ABAC policy allows it.
func Authorize(req AccessRequest) Decision {
	if !req.Subject.Role.Can(req.Action) {
		return deny(string(req.Action) + " is not permitted for role " + string(req.Subject.Role))
	}
	for _, p := range policies {
		if d := p(req); !d.Allow {
			return d
		}
	}
	return allow()
}
