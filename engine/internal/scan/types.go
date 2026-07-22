// Package scan defines the core data model, module contract, and orchestrator
// for the Bastionscan engine. Everything the engine knows how to check is a
// self-registering Module (see registry.go) — nothing is wired in by hand.
package scan

import "time"

// EngineVersion is surfaced in scan results and the /health endpoint.
const EngineVersion = "0.3.0"

// Status is the outcome of a single Finding.
type Status string

const (
	StatusPass Status = "pass"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusInfo Status = "info"
)

// Severity ranks how much a failing Finding matters.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Category groups Findings for scoring and UI. New categories can be added
// freely; the score aggregator discovers them from the Findings themselves.
type Category string

const (
	CategoryTransport  Category = "transport"
	CategoryHeaders    Category = "headers"
	CategoryDNS        Category = "dns"
	CategoryCookies    Category = "cookies"
	CategoryContent    Category = "content"
	CategoryDisclosure Category = "disclosure"
	CategorySurface    Category = "surface"
	CategoryIntel      Category = "intel"
	CategoryScam       Category = "scam"
	// CategoryActive is ownership-gated DAST: injection, XSS, CSRF, auth, etc.
	CategoryActive Category = "active"
)

// CategoryLabels are human-readable names for report rendering. A category
// without an entry falls back to its raw slug, so this map never blocks a new
// module from shipping.
var CategoryLabels = map[Category]string{
	CategoryTransport:  "Transport & TLS",
	CategoryHeaders:    "Response Headers",
	CategoryDNS:        "DNS & Email",
	CategoryCookies:    "Cookies",
	CategoryContent:    "Content Integrity",
	CategoryDisclosure: "Info Disclosure",
	CategorySurface:    "Attack Surface",
	CategoryIntel:      "Threat Intelligence",
	CategoryScam:       "Scam & Phishing",
	CategoryActive:     "Active AppSec (verified)",
}

// Finding is a single graded observation produced by a module.
type Finding struct {
	ID        string   `json:"id"`
	Module    string   `json:"module"`
	Category  Category `json:"category"`
	Title     string   `json:"title"`
	Status    Status   `json:"status"`
	Severity  Severity `json:"severity"`
	Points    int      `json:"points"`    // earned
	MaxPoints int      `json:"maxPoints"` // 0 => informational, excluded from scoring
	Detail    string   `json:"detail"`
	Fix       string   `json:"fix,omitempty"`
	Reference string   `json:"reference,omitempty"`
	Evidence  string   `json:"evidence,omitempty"`
}

// CategoryScore is the aggregated result for one Category.
type CategoryScore struct {
	Category Category `json:"category"`
	Label    string   `json:"label"`
	Score    int      `json:"score"` // 0–100
	Earned   int      `json:"earned"`
	Max      int      `json:"max"`
	Pass     int      `json:"pass"`
	Warn     int      `json:"warn"`
	Fail     int      `json:"fail"`
}

// ModuleRun records what each module did during a scan — for observability and
// to make the engine's dynamic behavior visible in the API response.
type ModuleRun struct {
	ID         string   `json:"id"`
	Category   Category `json:"category"`
	DurationMs int64    `json:"durationMs"`
	Findings   int      `json:"findings"`
	Error      string   `json:"error,omitempty"`
	Skipped    bool     `json:"skipped,omitempty"`
	SkipReason string   `json:"skipReason,omitempty"`
}

// ScanResult is the full graded report returned to callers.
type ScanResult struct {
	Target        string          `json:"target"`
	Host          string          `json:"host"`
	Domain        string          `json:"domain"`
	Profile       string          `json:"profile"`
	Verified      bool            `json:"verified"`
	Grade         string          `json:"grade"`
	Score         int             `json:"score"`
	Categories    []CategoryScore `json:"categories"`
	Findings      []Finding       `json:"findings"`
	Modules       []ModuleRun     `json:"modules"`
	Passed        int             `json:"passed"`
	Warnings      int             `json:"warnings"`
	Failed        int             `json:"failed"`
	ScannedAt     time.Time       `json:"scannedAt"`
	DurationMs    int64           `json:"durationMs"`
	EngineVersion string          `json:"engineVersion"`
}
