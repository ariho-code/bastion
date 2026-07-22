# Bastionscan — Website Security Scanner

A world-class website security platform. Grades any site A–F across TLS, security headers, DNS/email, cookies, and info disclosure — with copy-paste fixes.

Bastionscan is a **polyglot, three-tier system** — see [ARCHITECTURE.md](./ARCHITECTURE.md):

| Tier | Stack | Role |
| ---- | ----- | ---- |
| **Frontend** | Next.js + TypeScript (Vercel) | UI, SEO, and a fast passive scanner |
| **Risk brain** | Python · FastAPI (Render) | Risk scoring + prioritized remediation — [`brain/`](./brain) |
| **Scanning engine** | Go (Render) | Concurrent deep scanner, 12 self-registering modules — [`engine/`](./engine) |

The **standard scan** is instant and self-contained. The **Advanced Deep Scan**
(`/advanced`) drives the Go engine — deep TLS/cipher analysis, attack-surface
mapping (ports, subdomains, fingerprinting), exposed-file probing, DNS/email
auth, and threat intelligence — then the Python brain scores the risk and builds
a prioritized fix roadmap.

### Run the full stack locally

```bash
# 1) Engine (Go)          → http://localhost:8080
cd engine && go run ./cmd/server

# 2) Brain (Python)       → http://localhost:8090
cd brain && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ENGINE_URL=http://localhost:8080 uvicorn app.main:app --port 8090

# 3) Frontend (Next.js)   → http://localhost:3000
BASTION_BRAIN_URL=http://localhost:8090 npm run dev
# open http://localhost:3000/advanced
```

Deploy the engine + brain to Render with one click via [`render.yaml`](./render.yaml),
then set `BASTION_BRAIN_URL` on Vercel to the brain's URL.

---


## Deploy to Vercel (recommended, free)

1. Push this folder to a new GitHub repo:
   ```bash
   git init && git add . && git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/bastion.git
   git push -u origin main
   ```
2. Go to https://vercel.com/new, import the repo, and click Deploy. That's it.
3. Every future `git push` auto-deploys.

### Set your production URL

For correct canonical links, sitemap and social share cards, add an environment
variable in **Vercel → Settings → Environment Variables** (see `.env.example`):

```
NEXT_PUBLIC_SITE_URL=https://yourdomain.com
```

Shared scan results automatically generate a branded Open Graph image
(`/og?host=…&grade=A&score=95`) so links unfurl into a "yoursite.com scored A"
card on X, LinkedIn, Slack and iMessage. Traffic and Core Web Vitals are tracked
via Vercel Analytics and Speed Insights (enable them in your Vercel dashboard).

## Run locally

```bash
npm install
npm run dev
# open http://localhost:3000
```

## Accepting payments

Open `lib/brand.ts` and paste your Lemon Squeezy / Paddle / Polar / Gumroad
checkout URL into `checkoutUrl`. The Pro/Agency buttons will send customers
straight there. All three are Merchants of Record — they handle worldwide
tax/VAT and pay you out via PayPal (supported in Uganda).

## What it checks

- **Transport & TLS**: HTTPS, HTTP→HTTPS redirect, HSTS, TLS version, certificate validity
- **Response Headers**: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cross-origin isolation
- **DNS & Email**: SPF, DMARC, CAA records
- **Cookies**: Secure, HttpOnly, SameSite flags
- **Info Disclosure**: Server banner, X-Powered-By, security.txt, HTTP methods

## Rename to your own brand

Edit `lib/brand.ts` — every UI string is generated from it.
