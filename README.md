# Bastion — Website Security Scanner

A world-class, non-invasive website security scanner. Grades any site A–F across TLS, security headers, DNS/email, cookies, and info disclosure — with copy-paste fixes.

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
