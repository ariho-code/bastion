package scan

import (
	"context"
	"sort"
	"sync"
)

// Module is the contract every scanner plugin implements. Modules register
// themselves at init time (see Register), so adding a capability is a matter of
// dropping in a package and blank-importing it — no central switch to edit.
type Module interface {
	// ID is a stable, unique slug (e.g. "tls", "ports"). Used in Finding.Module.
	ID() string
	// Category is where this module's findings are grouped for scoring.
	Category() Category
	// Description is a one-line human summary for the /v1/modules endpoint.
	Description() string
	// MinLevel is the lowest scan Profile level at which this module runs.
	MinLevel() int
	// Supports reports whether the module is applicable to the given target.
	Supports(t *Target) bool
	// Run executes the checks and returns findings. Returning an error is
	// non-fatal — the engine records it and continues with other modules.
	Run(ctx context.Context, t *Target) ([]Finding, error)
}

var (
	regMu    sync.RWMutex
	registry = map[string]Module{}
)

// Register adds a module to the global registry. Intended to be called from a
// module package's init(). Panics on duplicate IDs to catch wiring mistakes at
// startup rather than silently dropping a scanner.
func Register(m Module) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[m.ID()]; dup {
		panic("scan: duplicate module id " + m.ID())
	}
	registry[m.ID()] = m
}

// Modules returns all registered modules, sorted by category then ID for
// deterministic ordering.
func Modules() []Module {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Module, 0, len(registry))
	for _, m := range registry {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category() != out[j].Category() {
			return out[i].Category() < out[j].Category()
		}
		return out[i].ID() < out[j].ID()
	})
	return out
}
