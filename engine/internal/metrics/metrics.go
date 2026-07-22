// Package metrics exposes engine telemetry in Prometheus text-exposition
// format. It's dependency-free (a few atomic counters plus a fixed-bucket
// histogram) so it adds nothing to the build, yet scrapes cleanly into
// Prometheus/Grafana for production observability.
package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics is the engine's telemetry registry. A single instance is shared and
// is safe for concurrent use.
type Metrics struct {
	start time.Time

	req2xx, req3xx, req4xx, req5xx atomic.Int64
	scansTotal, scanErrors         atomic.Int64
	rateLimited                    atomic.Int64
	inFlight                       atomic.Int64

	hist *histogram
}

// New creates a Metrics registry.
func New() *Metrics {
	return &Metrics{
		start: time.Now(),
		hist:  newHistogram([]float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 40, 60}),
	}
}

// ObserveRequest records a completed request by its status class.
func (m *Metrics) ObserveRequest(status int) {
	switch {
	case status >= 500:
		m.req5xx.Add(1)
	case status >= 400:
		m.req4xx.Add(1)
	case status >= 300:
		m.req3xx.Add(1)
	default:
		m.req2xx.Add(1)
	}
}

func (m *Metrics) IncScan()          { m.scansTotal.Add(1) }
func (m *Metrics) IncScanError()     { m.scanErrors.Add(1) }
func (m *Metrics) IncRateLimited()   { m.rateLimited.Add(1) }
func (m *Metrics) IncInFlight()      { m.inFlight.Add(1) }
func (m *Metrics) DecInFlight()      { m.inFlight.Add(-1) }
func (m *Metrics) ObserveScan(sec float64) { m.hist.observe(sec) }

// WritePrometheus renders all metrics in Prometheus exposition format.
func (m *Metrics) WritePrometheus(w io.Writer) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("# HELP bastionscan_requests_total Total HTTP requests by status class.\n")
	p("# TYPE bastionscan_requests_total counter\n")
	p("bastionscan_requests_total{class=\"2xx\"} %d\n", m.req2xx.Load())
	p("bastionscan_requests_total{class=\"3xx\"} %d\n", m.req3xx.Load())
	p("bastionscan_requests_total{class=\"4xx\"} %d\n", m.req4xx.Load())
	p("bastionscan_requests_total{class=\"5xx\"} %d\n", m.req5xx.Load())

	p("# HELP bastionscan_scans_total Total scans executed.\n")
	p("# TYPE bastionscan_scans_total counter\n")
	p("bastionscan_scans_total %d\n", m.scansTotal.Load())

	p("# HELP bastionscan_scan_errors_total Total scans that returned an error.\n")
	p("# TYPE bastionscan_scan_errors_total counter\n")
	p("bastionscan_scan_errors_total %d\n", m.scanErrors.Load())

	p("# HELP bastionscan_rate_limited_total Total requests rejected by the rate limiter.\n")
	p("# TYPE bastionscan_rate_limited_total counter\n")
	p("bastionscan_rate_limited_total %d\n", m.rateLimited.Load())

	p("# HELP bastionscan_requests_in_flight Requests currently being served.\n")
	p("# TYPE bastionscan_requests_in_flight gauge\n")
	p("bastionscan_requests_in_flight %d\n", m.inFlight.Load())

	p("# HELP bastionscan_uptime_seconds Seconds since the engine started.\n")
	p("# TYPE bastionscan_uptime_seconds gauge\n")
	p("bastionscan_uptime_seconds %d\n", int64(time.Since(m.start).Seconds()))

	p("# HELP bastionscan_go_goroutines Number of goroutines.\n")
	p("# TYPE bastionscan_go_goroutines gauge\n")
	p("bastionscan_go_goroutines %d\n", runtime.NumGoroutine())

	p("# HELP bastionscan_go_memstats_alloc_bytes Allocated heap bytes.\n")
	p("# TYPE bastionscan_go_memstats_alloc_bytes gauge\n")
	p("bastionscan_go_memstats_alloc_bytes %d\n", ms.Alloc)

	m.hist.write(w)
}

// --- fixed-bucket histogram --------------------------------------------------

type histogram struct {
	mu      sync.Mutex
	bounds  []float64
	counts  []int64 // len == len(bounds); cumulative computed at render
	sum     float64
	total   int64
}

func newHistogram(bounds []float64) *histogram {
	return &histogram{bounds: bounds, counts: make([]int64, len(bounds))}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	for i, b := range h.bounds {
		if v <= b {
			h.counts[i]++
		}
	}
}

func (h *histogram) write(w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(w, "# HELP bastionscan_scan_duration_seconds Scan wall-clock duration.\n")
	fmt.Fprintf(w, "# TYPE bastionscan_scan_duration_seconds histogram\n")
	for i, b := range h.bounds {
		fmt.Fprintf(w, "bastionscan_scan_duration_seconds_bucket{le=\"%g\"} %d\n", b, h.counts[i])
	}
	fmt.Fprintf(w, "bastionscan_scan_duration_seconds_bucket{le=\"+Inf\"} %d\n", h.total)
	fmt.Fprintf(w, "bastionscan_scan_duration_seconds_sum %g\n", h.sum)
	fmt.Fprintf(w, "bastionscan_scan_duration_seconds_count %d\n", h.total)
}
