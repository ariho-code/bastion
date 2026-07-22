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

## 5. Recommended production hardening (env vars)

Set these on the **engine** service in Render → Settings → Environment:

| Var | Example | Why |
| --- | ------- | --- |
| `ALLOWED_ORIGINS` | `https://yourdomain.com` | Lock CORS to your site |
| `API_KEYS` | `bk_live_xxx:pro,bk_live_yyy:agency` | Require keys for API access |
| `API_REQUIRE_KEY` | `true` | Reject anonymous API calls |
| `RATE_LIMIT_RPM` | `60` | Per-client request cap |
| `TRUSTED_PROXY` | `true` | Honor Render's `X-Forwarded-For` for real client IPs |

On the **brain**: set `ALLOWED_ORIGINS` to your domain too.

## 6. Custom domain (optional)

Render → service → **Settings → Custom Domains** → add `api.yourdomain.com`
(engine) and `brain.yourdomain.com`. Then point `BASTION_BRAIN_URL` at the
brain's custom domain.

---

**Rollback:** every service keeps its deploy history in Render → **Deploys** →
pick a previous build → **Redeploy**. Vercel has the same under **Deployments**.
