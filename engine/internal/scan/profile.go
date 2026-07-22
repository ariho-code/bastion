package scan

import "strings"

// Profile controls how deep a scan goes. Levels are cumulative: a Deep scan
// runs every module up to and including Deep. Active scans run the most
// intrusive modules and require an ownership-verified target.
type Profile struct {
	Name  string
	Level int
}

var (
	// ProfilePassive: zero-touch. Only observes what a normal client sees.
	ProfilePassive = Profile{"passive", 0}
	// ProfileStandard: the default. Light, safe, unauthenticated probing.
	ProfileStandard = Profile{"standard", 1}
	// ProfileDeep: thorough non-destructive analysis (cipher enumeration,
	// attack-surface mapping) — still safe to run against third parties.
	ProfileDeep = Profile{"deep", 2}
	// ProfileActive: intrusive checks that touch the target directly. Gated
	// behind domain-ownership verification (see Target.Verified).
	ProfileActive = Profile{"active", 3}
)

var profilesByName = map[string]Profile{
	ProfilePassive.Name:  ProfilePassive,
	ProfileStandard.Name: ProfileStandard,
	ProfileDeep.Name:     ProfileDeep,
	ProfileActive.Name:   ProfileActive,
}

// ParseProfile resolves a profile name, defaulting to Standard for empty or
// unknown input so the API never hard-fails on a typo.
func ParseProfile(name string) Profile {
	if p, ok := profilesByName[strings.ToLower(strings.TrimSpace(name))]; ok {
		return p
	}
	return ProfileStandard
}
