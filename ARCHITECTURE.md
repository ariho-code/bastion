# Bastionscan — Architecture

Bastionscan is a **polyglot, three-tier security platform**. Each tier is
written in the language best suited to its job, and each is independently
deployable, testable, and scalable.

```
┌──────────────────────────────┐     ┌───────────────────────────┐     ┌────────────────────────────┐
│  Next.js + TypeScript        │     │  Python · FastAPI         │     │  Go                        │
│  Frontend & orchestration    │ ──▶ │  Risk brain               │ ──▶ │  Scanning engine           │
│  (Vercel)                    │     │  (Render)                 │     │  (Render)                  │
│                              │     │                           │     │                            │
│  • Marketing + UX            │     │  • Weighted risk index    │     │  • Concurrent module fan-out│
│  • /advanced deep-scan UI    │     │  • Executive summary      │     │  • Deep TLS / ciphers      │
│  • /api/deep proxy           │     │  • Prioritized remediation│     │  • Attack-surface mapping  │
│  • Fast passive TS scanner   │     │  • /v1/analyze /v1/assess │     │  • Exposure + threat intel │
└──────────────────────────────┘     └───────────────────────────┘     └────────────────────────────┘
        browser / SEO                     explains & prioritizes              finds & grades
```

## Why three languages

This isn't language tourism — each boundary is a real seam:

| Tier | Language | Why |
| ---- | -------- | --- |
| **Frontend** | TypeScript / Next.js | SSR, SEO, i18n, and a rich interactive UI. Also hosts a fast, non-invasive passive scanner for instant results with zero backend dependency. |
| **Engine** | Go | Scanning is massively concurrent and network-bound — hundreds of independent probes (TLS handshakes, port checks, DNS lookups) that fan out at once. Go's goroutines make this natural; it compiles to a single static binary and is the lingua franca of modern security tooling. |
| **Brain** | Python / FastAPI | Risk scoring, narrative generation and (future) ML/CVE correlation are iteration-heavy, data-shaped work where Python's ecosystem shines. Kept off the latency-critical path so each side evolves independently. |

## Tier 1 — Frontend (Next.js, Vercel)

The product surface. It ships two scanning experiences:

- **Standard scan** — the original TypeScript engine in `lib/scanner/`, fully
  self-contained and serverless. Instant, non-invasive, always available.
- **Advanced deep scan** — `/advanced`, which proxies through `/api/deep` to
  the risk brain. Renders the risk gauge, category risk, and remediation roadmap.

The proxy keeps the backend URL server-side (`BASTION_BRAIN_URL`) and avoids CORS.

## Tier 2 — Risk brain (Python, FastAPI)

Turns raw findings into decisions. It never scans; it **explains and
prioritizes**:

- A transparent, weighted **risk index** (0–100) — `severity_weight ×
  category_weight`, warnings dampened, through a saturating curve.
- Credible **risk levels** (won't cry "Critical" over config hygiene alone).
- Executive **headline + summary**, per-category risk, strengths.
- A **priority-ordered remediation roadmap** (P1–P4, effort, points recovered).

`POST /v1/assess` is the one-call entrypoint: give it a target, it drives the
engine and returns scan + analysis together.

## Tier 3 — Scanning engine (Go, Render)

The performance core. A **self-registering module architecture**: every
capability implements the `scan.Module` interface and registers itself at init
time, so adding a scanner is a new package plus one blank import — no central
switch.

```
cmd/server            HTTP entrypoint + graceful shutdown
internal/scan         model, module registry, orchestrator, scoring, shared Env
internal/modules/*    self-registering plugins (tls, headers, cookies, dns,
                      fingerprint, content, cors, ports, subdomains, exposure,
                      intel, methods, discovery)
internal/netutil      SSRF guard + TOCTOU-safe HTTP client + DoH helpers
internal/api          thin HTTP layer (routing, CORS, rate limit)
internal/config       env-driven configuration (nothing hardcoded)
```

The orchestrator fans modules out concurrently with a bounded worker pool,
per-module timeouts, and panic isolation — one slow or buggy module can never
stall or crash a scan. Findings are aggregated and scored per category into an
A–F grade.

### Scan profiles

Depth is cumulative and gated:

`passive` → `standard` → `deep` → `active`

A `deep` scan runs every module up to `deep`. The most intrusive `active`
modules only run against **ownership-verified** targets — the ethical model
that separates "analyze anything safely" from "aggressively probe your own
assets."

### Active AppSec (ownership-gated DAST)

When a domain publishes the `bastionscan-verify` DNS TXT token, profile
`active` unlocks detection-grade modules (not weaponized exploits):

| Module | What it detects | Precision rule |
| ------ | --------------- | -------------- |
| `sqli` | SQL injection | Known DB error fingerprints only |
| `xss` | Reflected XSS | Unique canary reflected **unencoded** |
| `inject` | Path traversal / LFI | `/etc/passwd` or `win.ini` content shape |
| `csrf` | Missing CSRF tokens | Sensitive state-changing forms only |
| `authweak` | Default credentials | ≤5 pairs, lockout-aware, SafeMode default |
| `openredirect` | Open redirects | External canary host in Location |
| `jwtcheck` | JWT misconfig | `alg=none` / empty signature |
| `discovery` / `methods` | Attack surface | Content & HTTP method probes |

Enterprise **scope** (`excludePaths`, `includePaths`, `disableModules`,
`maxRequests`, `safeMode`) constrains every speculative request. The
`bastionscan` CLI and `/enterprise` console ship installers for macOS/Linux.

### Safety by design

- **SSRF guard** blocks loopback, private, link-local, and CGNAT ranges so the
  engine can't be pointed at internal infrastructure or cloud metadata.
- The shared HTTP client is **TOCTOU-safe**: it re-validates the resolved IP at
  dial time and connects to that exact IP, closing the DNS-rebinding hole.
- Per-IP **rate limiting** and strict per-scan/per-module **timeouts**.

## Data flow (advanced deep scan)

```
Browser → Next.js /api/deep → Brain /v1/assess → Engine /v1/scan
                                     │                   │
                                     │            concurrent modules
                                     │            (goroutine fan-out)
                                     ▼                   ▼
                              analyze(findings) ◀── graded ScanResult
                                     │
                                     ▼
                        { scan, analysis } → rendered dashboard
```

## Deployment

- **Frontend** → Vercel (auto-deploy on push). Set `BASTION_BRAIN_URL`.
- **Engine + Brain** → Render via [`render.yaml`](./render.yaml) (one-click
  Blueprint). The brain is wired to the engine automatically.

Each service has its own `Dockerfile`, health check, and unit tests. See
[`engine/README.md`](./engine/README.md) and [`brain/README.md`](./brain/README.md).
