package api

import (
	"github.com/ariho-code/bastionscan/engine/internal/auth"
	"github.com/ariho-code/bastionscan/engine/internal/authz"
)

// roleForTier maps an API plan tier to an authorization role. Anonymous callers
// keep the product's open scanning capability; agency keys are tenant admins.
func roleForTier(t auth.Tier) authz.Role {
	switch t {
	case auth.TierAgency:
		return authz.RoleAdmin
	case auth.TierPro, auth.TierFree:
		return authz.RoleScanner
	default:
		return authz.RoleAnonymous
	}
}

// subjectFor builds the authorization subject for a request identity. In local
// development (AllowPrivate) every caller is treated as an admin so tooling and
// the audit endpoint work without keys.
func (s *Server) subjectFor(id auth.Identity) authz.Subject {
	role := roleForTier(id.Tier)
	if s.cfg.AllowPrivate {
		role = authz.RoleAdmin
	}
	return authz.Subject{Role: role, Tier: string(id.Tier), Tenant: id.Tenant}
}
