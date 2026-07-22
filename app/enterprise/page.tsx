import type { Metadata } from "next";
import Link from "next/link";
import { brand } from "@/lib/brand";
import EnterpriseConsole from "@/components/EnterpriseConsole";

export const metadata: Metadata = {
  title: `Enterprise AppSec Console · ${brand.name}`,
  description:
    "Ownership-verified Active AppSec: scoped DAST for SQLi, XSS, CSRF, path traversal, JWT hygiene, and more — built for red teams, banks, and ecommerce.",
};

export default function EnterprisePage() {
  return (
    <main className="ent">
      <header className="ent-hero">
        <p className="ent-kicker">Enterprise · ownership-gated</p>
        <h1>Active AppSec console</h1>
        <p className="ent-sub">
          Prove domain ownership with a DNS TXT record, define scope exclusions for sensitive paths,
          then run detection-grade DAST against <em>your</em> systems only. Built for red teams,
          security companies, banks, ecommerce, and growing SaaS — with precision over noise.
        </p>
        <div className="ent-actions">
          <Link href="/advanced?profile=active" className="ent-btn primary">
            Open Advanced Active scan
          </Link>
          <Link href="/developers" className="ent-btn">
            API &amp; CLI docs
          </Link>
        </div>
      </header>

      <section className="ent-grid">
        <article className="ent-card">
          <h2>Hard ownership gate</h2>
          <p>
            Active modules never run without a live DNS TXT token on the registrable domain. The
            engine verifies ownership itself — no client flag is trusted in production.
          </p>
        </article>
        <article className="ent-card">
          <h2>Precision DAST</h2>
          <p>
            SQL injection (error fingerprints), reflected XSS (unencoded canaries), path traversal
            (passwd/win.ini content only), CSRF on sensitive forms, open redirects, JWT{" "}
            <code>alg=none</code>, default credentials (tiny list, lockout-aware).
          </p>
        </article>
        <article className="ent-card">
          <h2>Enterprise scope</h2>
          <p>
            Exclude <code>/billing</code>, partner APIs, or production admin. Disable individual
            modules. Cap request volume and delay. Safe mode is on by default.
          </p>
        </article>
        <article className="ent-card">
          <h2>Audit &amp; install</h2>
          <p>
            Tamper-evident audit chain, RBAC/ABAC, Prometheus metrics. Install the CLI on macOS or
            Linux with one script for CI and air-gapped red-team laptops.
          </p>
        </article>
      </section>

      <EnterpriseConsole />

      <section className="ent-modules">
        <h2>Active modules (verified only)</h2>
        <ul>
          <li>
            <strong>sqli</strong> — safe quote probes; report only on known DB error signatures
          </li>
          <li>
            <strong>xss</strong> — unique canary must reflect unencoded
          </li>
          <li>
            <strong>inject</strong> — path traversal / LFI with OS file fingerprints
          </li>
          <li>
            <strong>csrf</strong> — anti-CSRF tokens on password/payment forms
          </li>
          <li>
            <strong>authweak</strong> — ≤5 default pairs, 1.5s spacing, stop on lockout
          </li>
          <li>
            <strong>openredirect</strong> — external canary in Location / meta refresh
          </li>
          <li>
            <strong>jwtcheck</strong> — alg=none / empty signature detection
          </li>
          <li>
            <strong>discovery</strong> · <strong>methods</strong> — content &amp; HTTP method surface
          </li>
        </ul>
      </section>

      <section className="ent-install">
        <h2>Install CLI (macOS / Linux)</h2>
        <pre className="ent-pre">{`curl -fsSL https://raw.githubusercontent.com/ariho-code/bastion/main/scripts/install.sh | bash`}</pre>
        <p>
          Or from a clone: <code>./scripts/install.sh</code> — installs{" "}
          <code>bastionscan</code> to <code>~/.local/bin</code>. Then:
        </p>
        <pre className="ent-pre">{`bastionscan verify example.com
# publish the TXT record, then:
bastionscan active example.com --exclude /billing --exclude /admin/prod
bastionscan active example.com --disable authweak,discovery --safe`}</pre>
      </section>

      <style>{`
        .ent { max-width: 960px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }
        .ent-hero { margin-bottom: 2rem; }
        .ent-kicker { text-transform: uppercase; letter-spacing: .08em; font-size: .75rem; color: #64748b; font-weight: 600; }
        .ent h1 { font-size: clamp(1.75rem, 4vw, 2.4rem); margin: .4rem 0 1rem; letter-spacing: -0.02em; }
        .ent-sub { color: #94a3b8; line-height: 1.6; max-width: 48rem; }
        .ent-actions { display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1.25rem; }
        .ent-btn { display: inline-flex; align-items: center; padding: .65rem 1rem; border-radius: 10px; border: 1px solid rgba(148,163,184,.25); color: #e2e8f0; text-decoration: none; font-weight: 600; font-size: .9rem; }
        .ent-btn.primary { background: linear-gradient(135deg, #2563eb, #7c3aed); border-color: transparent; color: #fff; }
        .ent-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0; }
        .ent-card { background: rgba(15,23,42,.65); border: 1px solid rgba(148,163,184,.15); border-radius: 14px; padding: 1.1rem 1.15rem; }
        .ent-card h2 { font-size: 1rem; margin: 0 0 .5rem; }
        .ent-card p { margin: 0; color: #94a3b8; font-size: .9rem; line-height: 1.55; }
        .ent-modules, .ent-install { margin-top: 2.5rem; }
        .ent-modules ul { padding-left: 1.1rem; color: #cbd5e1; line-height: 1.7; }
        .ent-pre { background: #0b1220; border: 1px solid rgba(148,163,184,.18); border-radius: 12px; padding: 1rem 1.1rem; overflow-x: auto; font-size: .82rem; color: #e2e8f0; }
        code { font-size: .88em; color: #93c5fd; }
      `}</style>
    </main>
  );
}
