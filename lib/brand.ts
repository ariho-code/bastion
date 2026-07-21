// Single source of truth for branding. Change these to rebrand instantly.

export const SITE_URL =
  process.env.NEXT_PUBLIC_SITE_URL || "https://bastion-arihos-projects.vercel.app";

export const brand = {
  name: "Bastion",
  tagline: "Website security, graded in seconds.",
  shortDescription:
    "Bastion scans any website's live security posture — headers, TLS, DNS, email spoofing protection and more — and grades it A–F with copy-paste fixes.",
  longDescription:
    "Bastion is a fast, non-invasive website security scanner. Paste a URL and get an instant A–F security grade across five categories — Transport (HTTPS/TLS), Response Headers, DNS & Email, Cookies, and Information Disclosure — each with a plain-English explanation and a copy-paste fix. Bastion reads only what a normal browser sees, so it is safe and legal to run on any site.",
  url: SITE_URL,
  domainSuggestion: "bastionscan.com",
  contactEmail: "security@bastionscan.com",
  twitter: "@bastionscan",
  // 💰 Paste your Lemon Squeezy / Paddle / Polar / Gumroad checkout link here to accept payments.
  checkoutUrl: "",
  keywords: [
    "website security scanner",
    "security headers checker",
    "HTTP security headers",
    "TLS SSL checker",
    "HSTS checker",
    "Content Security Policy",
    "CSP checker",
    "SPF DMARC checker",
    "security grade",
    "website vulnerability scan",
    "check website security",
    "security.txt",
  ],
} as const;

export type Brand = typeof brand;
