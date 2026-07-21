import { brand } from "@/lib/brand";

const FAQS: { q: string; a: string }[] = [
  {
    q: "Is it safe and legal to scan any website?",
    a: `Yes. ${brand.name} only reads the public information a normal browser already receives — response headers, the TLS certificate, and public DNS records. It never logs in, submits forms, brute-forces, or probes for vulnerabilities, so it places no meaningful load on the target and stays firmly on the right side of the line.`,
  },
  {
    q: "What exactly does Bastion check?",
    a: "Over 20 signals across five categories: Transport (HTTPS, HTTP→HTTPS redirect, HSTS, TLS version and certificate validity), Response Headers (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cross-origin isolation), DNS & Email (SPF, DMARC, CAA), Cookies (Secure, HttpOnly, SameSite), and Information Disclosure (server banners, X-Powered-By, security.txt, risky HTTP methods).",
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

export default function Faq() {
  return (
    <section id="faq" className="faq">
      <div className="section-head">
        <span className="eyebrow">FAQ</span>
        <h2>Questions, answered</h2>
      </div>
      <div className="faq-list">
        {FAQS.map((f, i) => (
          <details key={i} className="faq-item">
            <summary>
              {f.q}
              <span className="faq-plus" aria-hidden="true" />
            </summary>
            <p>{f.a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
