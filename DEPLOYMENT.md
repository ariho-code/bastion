# Going Live — Deployment Guide

Bastionscan runs as three deployables:

| Service | Where | What |
| ------- | ----- | ---- |
| Frontend (Next.js) | **Vercel** | The site + `/advanced` UI |
| Scanning engine (Go) | **Render** | Deep scanner API |
| Risk brain (Python) | **Render** | Risk scoring + remediation |

The frontend is already on Vercel. This guide brings the **Go engine** and
**Python brain** live on Render and wires them to the frontend.

---

## 1. Prerequisites

- The repo is on GitHub (`ariho-code/bastion`) — ✅ already pushed.
- A free [Render](https://render.com) account (sign in with GitHub).
- Access to the Vercel project's environment variables.

## 2. Deploy the backend (one-click Blueprint)

Render reads [`render.yaml`](./render.yaml) and creates **both** services at once.

1. Render Dashboard → **New +** → **Blueprint**.
2. Connect GitHub and pick the **`ariho-code/bastion`** repo.
3. Render shows two services from the blueprint:
   - `bastionscan-engine` (Docker, `./engine`)
   - `bastionscan-brain` (Docker, `./brain`)
4. Click **Apply**. Render builds both Docker images and deploys them.
   `ENGINE_URL` on the brain is wired to the engine automatically.
5. When both show **Live**, note their URLs (e.g.):
   - Engine: `https://bastionscan-engine.onrender.com`
   - Brain:  `https://bastionscan-brain.onrender.com`

### Verify the backend

```bash
curl https://bastionscan-engine.onrender.com/health
# {"status":"ok","modules":9,...}

curl https://bastionscan-brain.onrender.com/health
# {"status":"ok","engine_reachable":true,...}

# Full end-to-end:
curl -s https://bastionscan-brain.onrender.com/v1/assess \
  -H 'content-type: application/json' \
  -d '{"target":"example.com","profile":"deep"}' | head -c 400
```

## 3. Wire the frontend (Vercel)

1. Vercel → your project → **Settings → Environment Variables**.
2. Add for **Production** (and Preview):
   ```
   BASTION_BRAIN_URL = https://bastionscan-brain.onrender.com
   ```
3. **Redeploy** (Deployments → ⋯ → Redeploy, or just `git push`).
4. Open `https://yourdomain.com/advanced` and run a deep scan. 🎉

## 4. Free-tier notes

- Free Render services **sleep after ~15 min idle**. The first scan after a nap
  wakes them and takes ~30–60s. Upgrade to a paid instance for always-on.
- Both services are in the `oregon` region by default (edit `render.yaml` to
  change). Keep engine + brain in the same region for low latency.

## 5. AI environment variables (put these on the **brain**, not the engine)

The LLM, RAG memory, and learning store all run inside **`bastionscan-brain`**.
The Go **engine** does not need AI keys.

### Where to click (Render)

1. [Render Dashboard](https://dashboard.render.com) → open **`bastionscan-brain`**
2. **Environment** (left sidebar)
3. **Add Environment Variable** for each row below
4. **Save Changes** → service redeploys automatically

### Required for DeepSeek (default)

| Variable | Service | Example | Notes |
| -------- | ------- | ------- | ----- |
| `DEEPSEEK_API_KEY` | **brain only** | `sk-...` | From [platform.deepseek.com](https://platform.deepseek.com) |
| `AI_PROVIDER` | brain | `deepseek` | Default; already in `render.yaml` |
| `AI_ENABLED` | brain | `true` | |
| `AI_ON_ASSESS` | brain | `true` | Attach AI insights to every `/v1/assess` |
| `BASTION_LEARNING_DIR` | brain | `/var/data/bastion-learning` | Persist feedback + RAG; use a disk if possible |

### Later — switch models (same brain service)

| To use | Set on **brain** |
| ------ | ---------------- |
| **Grok / xAI** | `AI_PROVIDER=grok` and `XAI_API_KEY=...` |
| **Claude** | `AI_PROVIDER=claude` and `ANTHROPIC_API_KEY=...` |
| **Optional remote embeddings** | `EMBEDDING_API_KEY` + `EMBEDDING_BASE_URL` (OpenAI-compatible). DeepSeek has no public embeddings API; local hashing RAG works without this. |

### Do **not** put AI keys on

- `bastionscan-engine` (Go) — no AI runtime
- Vercel frontend — keys must stay server-side on the brain

### Verify AI is live

```bash
curl -s https://bastionscan-brain.onrender.com/health | jq .ai,.rag,.learning
# ai.enabled should be true when DEEPSEEK_API_KEY is set
```

### Persistent learning disk (brain) — best option: Blueprint

**Best option:** define the disk in [`render.yaml`](./render.yaml) on
**`bastionscan-brain`** with **plan: starter** + a **1 GB disk** at `/var/data`.

Free web services **cannot** attach disks (Render policy). Files under `/tmp`
are wiped on every redeploy/sleep. The blueprint is already set up as:

| Setting | Value |
| ------- | ----- |
| Service | `bastionscan-brain` only (not engine) |
| Plan | `starter` |
| Disk name | `bastion-learning` |
| Mount path | `/var/data` |
| Env | `BASTION_LEARNING_DIR=/var/data/bastion-learning` |

#### Apply it

1. Push `main` (already includes the disk block).
2. Render Dashboard → your **Blueprint** → **Manual Sync** (or wait for auto).
3. Approve the plan upgrade + disk if Render prompts for billing.
4. Confirm env secrets: `DEEPSEEK_API_KEY` (brain), `VERIFY_SECRET` (engine).
5. Wait until brain is **Live**.

#### If the service already exists without a disk

**Preferred:** Blueprint sync (above) so IaC stays source of truth.

**Manual fallback (same result):**
1. Open **`bastionscan-brain`** → **Settings** → instance type → **Starter**
2. **Disks** → **Add Disk**
   - Mount path: **`/var/data`**
   - Size: **1 GB**
3. Environment: `BASTION_LEARNING_DIR=/var/data/bastion-learning`
4. Save / redeploy

#### Verify

```bash
curl -s https://bastionscan-brain.onrender.com/health | jq .learning
# Expect:
#   "dir": "/var/data/bastion-learning",
#   "persistent_disk": true
```

After one Advanced scan + a “Looks right / Looks wrong” click, restart the
service once — feedback counts should **not** reset to zero.

**Never** attach this disk to the Go **engine** — only the brain writes learning data.

---

## 6. Recommended production hardening (env vars)

Set these on the **engine** service in Render → Settings → Environment:

| Var | Example | Why |
| --- | ------- | --- |
| `ALLOWED_ORIGINS` | `https://yourdomain.com` | Lock CORS to your site |
| `API_KEYS` | `bk_live_xxx:pro,bk_live_yyy:agency` | Require keys for API access |
| `API_REQUIRE_KEY` | `true` | Reject anonymous API calls |
| `RATE_LIMIT_RPM` | `60` | Per-client request cap |
| `TRUSTED_PROXY` | `true` | Honor Render's `X-Forwarded-For` for real client IPs |
| `VERIFY_SECRET` | long random string | DNS ownership token HMAC secret |

On the **brain**: set `ALLOWED_ORIGINS` to your domain too.

## 6. Custom domain (optional)

Render → service → **Settings → Custom Domains** → add `api.yourdomain.com`
(engine) and `brain.yourdomain.com`. Then point `BASTION_BRAIN_URL` at the
brain's custom domain.

---

## Troubleshooting

**"could not reach scanning engine: Name or service not known"** — the brain
can't resolve the engine. The blueprint wires `ENGINE_URL` to the engine over
Render's private network (`bastionscan-engine:<port>`). If that doesn't resolve
in your setup, override it on the **brain** service in Render → Settings →
Environment:

```
ENGINE_URL = https://bastionscan-engine.onrender.com   # the engine's PUBLIC url
```

Then **Manual Deploy → Clear build cache & deploy** the brain. Confirm with
`curl https://bastionscan-brain.onrender.com/health` → `"engine_reachable":true`.

**Scan times out on first use** — free instances were asleep; the first request
wakes them (~30–60s). Retry, or upgrade to a paid instance for always-on.

---

**Rollback:** every service keeps its deploy history in Render → **Deploys** →
pick a previous build → **Redeploy**. Vercel has the same under **Deployments**.
