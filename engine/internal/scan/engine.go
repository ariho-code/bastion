package scan

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Options tune the orchestrator. Zero values fall back to sane defaults so the
// engine is usable without configuration.
type Options struct {
	MaxConcurrency int           // max modules running at once
	ModuleTimeout  time.Duration // per-module hard deadline
	ScanTimeout    time.Duration // whole-scan hard deadline
}

func (o Options) withDefaults() Options {
	if o.MaxConcurrency <= 0 {
		o.MaxConcurrency = 8
	}
	if o.ModuleTimeout <= 0 {
		o.ModuleTimeout = 20 * time.Second
	}
	if o.ScanTimeout <= 0 {
		o.ScanTimeout = 60 * time.Second
	}
	return o
}

// Engine runs registered modules against a target and assembles a graded
// report. It holds no per-scan state, so a single Engine is safe for concurrent
// use across many requests.
type Engine struct {
	opts Options
}

// NewEngine builds an Engine from the given Options.
func NewEngine(opts Options) *Engine {
	return &Engine{opts: opts.withDefaults()}
}

// Run executes an entire scan: it selects applicable modules for the profile,
// fans them out concurrently (bounded), aggregates their findings, and scores
// the result. Individual module failures never fail the whole scan.
func (e *Engine) Run(ctx context.Context, t *Target, profile Profile) *ScanResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, e.opts.ScanTimeout)
	defer cancel()

	mods := Modules()
	sem := make(chan struct{}, e.opts.MaxConcurrency)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		findings []Finding
		runs     []ModuleRun
	)

	for _, m := range mods {
		// Profile gating: cumulative levels, with Active requiring verification.
		if m.MinLevel() > profile.Level {
			continue
		}
		if m.MinLevel() >= ProfileActive.Level && !t.Verified {
			mu.Lock()
			runs = append(runs, ModuleRun{
				ID: m.ID(), Category: m.Category(),
				Skipped: true, SkipReason: "requires an ownership-verified target",
			})
			mu.Unlock()
			continue
		}
		if !m.Supports(t) {
			mu.Lock()
			runs = append(runs, ModuleRun{
				ID: m.ID(), Category: m.Category(),
				Skipped: true, SkipReason: "not applicable to this target",
			})
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			run := e.runModule(ctx, m, t)
			mu.Lock()
			findings = append(findings, run.findings...)
			runs = append(runs, run.summary)
			mu.Unlock()
		}(m)
	}
	wg.Wait()

	// Normalize to empty (non-nil) slices so the JSON API always returns arrays.
	if findings == nil {
		findings = []Finding{}
	}
	if runs == nil {
		runs = []ModuleRun{}
	}
	sortFindings(findings)
	cats, overall := scoreByCategory(findings)

	var pass, warn, fail int
	for _, f := range findings {
		switch f.Status {
		case StatusPass:
			pass++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		}
	}

	return &ScanResult{
		Target:        t.Raw,
		Host:          t.Host,
		Domain:        t.Domain,
		Profile:       profile.Name,
		Grade:         GradeFromScore(overall),
		Score:         overall,
		Categories:    cats,
		Findings:      findings,
		Modules:       runs,
		Passed:        pass,
		Warnings:      warn,
		Failed:        fail,
		ScannedAt:     started.UTC(),
		DurationMs:    time.Since(started).Milliseconds(),
		EngineVersion: EngineVersion,
	}
}

type moduleOutcome struct {
	findings []Finding
	summary  ModuleRun
}

// runModule executes one module with its own timeout and panic isolation, so a
// buggy or slow plugin can never take down a scan.
func (e *Engine) runModule(ctx context.Context, m Module, t *Target) (out moduleOutcome) {
	mctx, cancel := context.WithTimeout(ctx, e.opts.ModuleTimeout)
	defer cancel()
	start := time.Now()

	out.summary = ModuleRun{ID: m.ID(), Category: m.Category()}
	defer func() {
		if r := recover(); r != nil {
			out.findings = nil
			out.summary.Error = fmt.Sprintf("panic: %v", r)
		}
		out.summary.DurationMs = time.Since(start).Milliseconds()
		out.summary.Findings = len(out.findings)
	}()

	found, err := m.Run(mctx, t)
	if err != nil {
		out.summary.Error = err.Error()
	}
	// Stamp the module ID on every finding so provenance is never lost.
	for i := range found {
		if found[i].Module == "" {
			found[i].Module = m.ID()
		}
		if found[i].Category == "" {
			found[i].Category = m.Category()
		}
	}
	out.findings = found
	return out
}
