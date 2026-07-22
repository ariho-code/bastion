# Bastionscan Brain

The analysis layer of Bastionscan — a small **FastAPI** service (Python) that
turns the Go engine's raw findings into decision-ready risk intelligence:

- a transparent, weighted **risk index** (0–100) and risk level,
- an executive **summary and headline**,
- per-category risk,
- and a **prioritized remediation roadmap** (P1–P4, effort, points recovered).

It pairs with the Go engine: the engine finds and grades, the brain explains and
prioritizes. Two languages, each doing what it's best at.

## Why a separate Python service

Risk scoring, narrative generation, and (in future) ML/CVE correlation are
iteration-heavy, data-shaped work where Python's ecosystem shines. Keeping it
out of the latency-critical Go scanner lets each scale and evolve independently.

## API

| Method | Path          | Purpose                                             |
| ------ | ------------- | --------------------------------------------------- |
| GET    | `/health`     | Liveness + whether the engine is reachable          |
| POST   | `/v1/analyze` | Analyze an engine `ScanResult` you already have     |
| POST   | `/v1/assess`  | Give `{target, profile}` — brain drives the engine then analyzes |

```bash
# End-to-end: one call, target in, scan + analysis out.
curl -s localhost:8090/v1/assess \
  -H 'content-type: application/json' \
  -d '{"target":"example.com","profile":"deep"}' | jq .analysis
```

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ENGINE_URL=http://localhost:8080 uvicorn app.main:app --port 8090 --reload
pytest                                   # unit tests (no network)
docker build -t bastionscan-brain . && docker run -p 8090:8090 bastionscan-brain
```

## Configuration

| Var               | Default                 | Meaning                          |
| ----------------- | ----------------------- | -------------------------------- |
| `ENGINE_URL`      | `http://localhost:8080` | Base URL of the Go engine        |
| `PORT`            | `8090`                  | Listen port (Render injects it)  |
| `ALLOWED_ORIGINS` | `*`                     | CORS allowlist (comma-separated) |
| `ENGINE_TIMEOUT`  | `90`                    | Seconds to wait on the engine    |

## Risk model

Each open issue contributes `severity_weight × category_weight` (warnings at
half weight) to a raw figure, mapped through a saturating curve to 0–100. The
weights live in `app/analyzer.py` and are deliberately explainable — no black
box.
