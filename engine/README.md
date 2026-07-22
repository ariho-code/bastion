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
| `RATE_LIMIT_RPM`  | `60`    | Per-IP requests/min (`0` disables)       |
| `MAX_CIPHER_TESTS`| `40`    | Cap on TLS cipher probes                 |

## Modules

- **tls** — deep TLS analysis: protocol-version enumeration, live cipher-suite
  probing, certificate-chain validation, key strength, signature algorithm,
  forward secrecy, and expiry.

_More modules land on the roadmap: attack-surface mapping, active safe checks,
and threat intelligence._
