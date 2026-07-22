# Bastionscan Engine

A concurrent, plugin-based security-scanning engine written in Go. It powers the
deep analysis behind Bastionscan — the kind of transport, attack-surface, and
threat-intelligence inspection that goes well beyond a normal header check.

## Why Go

Scanning is embarrassingly parallel and network-bound: hundreds of independent
probes (protocol handshakes, port checks, DNS lookups) that should fan out at
once. Go's goroutines make that natural, it compiles to a single static binary,
and it's the lingua franca of modern security tooling. The engine runs each
module concurrently with per-module timeouts and panic isolation, so one slow or
misbehaving check never stalls or crashes a scan.

## Architecture

```
cmd/server            HTTP entrypoint + graceful shutdown
internal/scan         core model, module registry, orchestrator, scoring
internal/modules/*    self-registering scanner plugins (tls, …)
internal/netutil      SSRF guard + shared network helpers
internal/api          thin HTTP layer (routing, CORS, rate limit)
internal/config       env-driven configuration (nothing hardcoded)
```

Every capability is a `scan.Module` that registers itself at init time. Adding
one means dropping in a package and a single blank import — there is no central
switch to edit. Scan depth is controlled by **profiles** (`passive` → `standard`
→ `deep` → `active`); the most intrusive `active` modules only run against
ownership-verified targets.

## API

| Method | Path          | Purpose                                   |
| ------ | ------------- | ----------------------------------------- |
| GET    | `/health`     | Liveness + registered-module count        |
| GET    | `/v1/modules` | Self-describing capability list           |
| POST   | `/v1/scan`    | Run a scan (`{ target, profile, verified }`) |
| GET    | `/v1/scan`    | Same, via `?target=&profile=` for testing |

```bash
curl 'localhost:8080/v1/scan?target=example.com&profile=deep'
```

## Run

```bash
go run ./cmd/server                 # localhost:8080
go test ./...                       # unit tests
docker build -t bastionscan-engine . && docker run -p 8080:8080 bastionscan-engine
```

## Configuration

All via environment variables (with safe defaults):

| Var               | Default | Meaning                                  |
| ----------------- | ------- | ---------------------------------------- |
| `PORT`            | `8080`  | Listen port (Render injects this)        |
| `ALLOWED_ORIGINS` | `*`     | CORS allowlist (comma-separated)         |
| `ALLOW_PRIVATE`   | `false` | Let the SSRF guard reach private hosts (**dev only**) |
| `MAX_CONCURRENCY` | `8`     | Parallel modules per scan                |
| `MODULE_TIMEOUT`  | `20s`   | Per-module deadline                      |
| `SCAN_TIMEOUT`    | `60s`   | Whole-scan deadline                      |
| `MAX_CIPHER_TESTS`| `40`    | Cap on TLS cipher probes                 |
| `API_KEYS`        | —       | `key:tier,…` (tier = `free`\|`pro`\|`agency`) |
| `API_REQUIRE_KEY` | `false` | Reject anonymous calls to `/v1/scan`     |
| `TRUSTED_PROXY`   | `false` | Honor `X-Forwarded-For` (only behind a trusted LB) |
| `RATE_LIMIT_RPM`  | `60`    | Anonymous per-client requests/min (`0` disables) |
| `RATE_LIMIT_RPM_FREE` | `120`   | `free` tier requests/min             |
| `RATE_LIMIT_RPM_PRO`  | `600`   | `pro` tier requests/min              |
| `RATE_LIMIT_RPM_AGENCY` | `3000` | `agency` tier requests/min          |
| `TARGET_COOLDOWN`  | `8s`    | Min interval between scans of the same host |

## Security & hardening

The engine is built to be exposed publicly and abused-at:

- **Tiered API keys** — pass `Authorization: Bearer <key>` or `X-API-Key`. Keys
  are matched in constant time; tiers carry their own rate limits. Set
  `API_REQUIRE_KEY=true` to lock down `/v1/scan`.
- **Per-tier rate limiting** with standard `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`, `X-RateLimit-Reset` and `Retry-After` (429) headers,
  keyed by API key (or client IP when anonymous).
- **Security response headers** on every response (CSP, HSTS, `nosniff`,
  `X-Frame-Options: DENY`, Referrer-Policy, Permissions-Policy) — the scanner
  dogfoods the controls it audits.
- **SSRF guard + TOCTOU-safe dialing**, **request IDs** (`X-Request-ID`), and
  **structured JSON access logs** for correlation.
- `TRUSTED_PROXY` gates `X-Forwarded-For` so rate-limit keys can't be spoofed.
- **Anti-abuse**: input validation rejects embedded credentials and non-web
  service ports; a **per-target cooldown** stops the engine being weaponized to
  flood one victim; every scan emits a structured **audit-trail** log line.

## Modules

- **tls** — deep TLS analysis: protocol-version enumeration, live cipher-suite
  probing, certificate-chain validation, key strength, signature algorithm,
  forward secrecy, and expiry.

_More modules land on the roadmap: attack-surface mapping, active safe checks,
and threat intelligence._
