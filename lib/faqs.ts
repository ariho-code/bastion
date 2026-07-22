import { brand } from "./brand";

export interface Faq {
  q: string;
  a: string;
}

/** Single source of truth for FAQs — rendered in the UI and emitted as
 *  FAQPage structured data so they can win rich results in search. */
export const FAQS: Faq[] = [
  {
    q: "Is it safe and legal to scan any website?",
    a: `Yes. ${brand.name} only reads the public information a normal browser already receives — response headers, the TLS certificate, and public DNS records. It never logs in, submits forms, brute-forces, or probes for vulnerabilities, so it places no meaningful load on the target and stays firmly on the right side of the line.`,
  },
  {
    q: "What exactly does Bastionscan check?",
    a: "28 deep signals across six categories: Transport & TLS (HTTPS, HSTS, TLS version, certificate validity, forward secrecy, OCSP stapling and key strength), Response Headers (CSP depth analysis, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cross-origin isolation), DNS & Email (DNSSEC, SPF, DMARC, CAA, DKIM, MTA-STS, SMTP TLS-RPT and BIMI), Cookies (Secure, HttpOnly, SameSite), Content Integrity (live mixed-content detection), and Information Disclosure (server banners, X-Powered-By, security.txt, risky HTTP methods).",
  },
  {
    q: "How is the grade calculated?",
    a: "Each check carries a weight based on real-world impact. We total the points you earn against the maximum, produce a 0–100 score per category and overall, then map it to a letter grade (A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55, otherwise F). Informational checks never count against you.",
  },
  {
    q: "Do I need an account or credit card?",
    a: "No. Scanning is free and requires neither. You only create an account if you upgrade to Pro or Agency for continuous monitoring, bulk scanning, and white-label reports.",
  },
  {
    q: "Can I use the reports with clients?",
    a: "Absolutely. Every scan can be exported as a clean PDF. On the Agency plan you can fully white-label reports with your own logo and send scheduled updates to clients automatically.",
  },
  {
    q: "How accurate are the fixes?",
    a: "Each finding includes a copy-paste remediation for common stacks (nginx, Apache, Express, PHP, DNS). They are sensible, production-tested defaults — always review them against your own configuration before deploying.",
  },
];
