import type { Metadata } from "next";
import Link from "next/link";
import { brand } from "@/lib/brand";
import EnterpriseConsole from "@/components/EnterpriseConsole";
import Icon, { type IconName } from "@/components/Icon";

export const metadata: Metadata = {
  title: `Enterprise AppSec · ${brand.name}`,
  description:
    "Ownership-verified red-team simulation for banks, ecommerce, and SaaS — stealth recon, DAST, bounded load, AI learning. White/gray hat defense against black-hat TTPs.",
};

const CAPS: { icon: IconName; title: string; body: string }[] = [
  {
    icon: "shield-check",
    title: "DNS ownership gate",
    body: "Active & aggressive probes never run until the domain publishes bastionscan-verify. Engine verifies — clients cannot spoof.",
  },
  {
    icon: "zap",
    title: "Attacker-TTP simulation",
    body: "SQLi, XSS, LFI, CSRF, Host injection, WAF recon, GraphQL, JWT, default creds — detection-grade mimics of real intrusion paths.",
  },
  {
    icon: "activity",
    title: "Stealth + intensity",
    body: "Low-and-slow jitter and UA rotation validate bot/WAF rules. Aggressive unlocks hard-capped concurrent load with explicit consent.",
  },
  {
    icon: "gauge",
    title: "Scope exclusions",
    body: "Exclude /billing, partner APIs, prod admin. Include-only allow-lists. Disable modules. Safe by default.",
  },
  {
    icon: "sparkles",
    title: "AI that learns",
    body: "DeepSeek (or Grok/Claude) + RAG memory + FP model trained on your true/false positive labels.",
  },
  {
    icon: "code",
    title: "CI / CLI gate",
    body: "bastionscan active --gate-grade B fails pipelines when posture slips. Same engine Apple-scale teams expect: repeatable, auditable.",
  },
];

export default function EnterprisePage() {
  return (
    <main>
      <section className="hero">
        <div className="hero-inner">
          <div className="badge">
            <span className="badge-dot" />
            Enterprise · white / gray hat · ownership-gated
          </div>
          <h1>
            Test like a black hat.
            <br />
            <span className="grad">Defend like a platform team.</span>
          </h1>
          <p className="hero-sub">
            Bastionscan gives banks, marketplaces, and SaaS companies the same class of checks
            sophisticated attackers use — only after you prove you own the asset, and only inside
            the scope you define. No third-party firepower. No open DDoS kit. Real TTPs, hard caps,
            full audit trail.
          </p>
          <div className="hero-trust">
            <span>DNS-verified Active</span>
            <span className="sep">·</span>
            <span>Stealth recon</span>
            <span className="sep">·</span>
            <span>Bounded load opt-in</span>
            <span className="sep">·</span>
            <span>AI + RAG learning</span>
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", marginTop: "1.5rem" }}>
            <Link href="/advanced?profile=active" className="btn-primary">
              Open Active AppSec
            </Link>
            <Link href="/developers" className="btn-ghost">
              API &amp; CLI
            </Link>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="section-inner">
          <h2 className="section-title">Built for teams that ship at scale</h2>
          <p className="section-sub">
            Jumia, Amazon-style marketplaces, Apple-grade product orgs, AI labs — same problem:
            find the hole before a black hat does, without torching production.
          </p>
          <div className="grid-3" style={{ marginTop: "1.75rem" }}>
            {CAPS.map((c) => (
              <article key={c.title} className="card">
                <div className="card-icon">
                  <Icon name={c.icon} size={22} />
                </div>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section" id="console">
        <div className="section-inner">
          <h2 className="section-title">Enterprise workbench</h2>
          <p className="section-sub">
            Verify ownership, set exclusions, pick a vertical, launch Active with the intensity your
            change window allows.
          </p>
          <EnterpriseConsole />
        </div>
      </section>

      <section className="section">
        <div className="section-inner">
          <h2 className="section-title">Intensity model</h2>
          <div className="grid-3" style={{ marginTop: "1.25rem" }}>
            <article className="card">
              <h3>Safe</h3>
              <p>
                Canaries, error fingerprints, stealth on. Default for continuous monitoring and PCI
                evidence packs.
              </p>
            </article>
            <article className="card">
              <h3>Thorough</h3>
              <p>
                Higher path budget, stealth jitter — validates WAF/bot rules the way recon bots
                actually behave.
              </p>
            </article>
            <article className="card">
              <h3>Aggressive</h3>
              <p>
                Max authorized probe budget. Optional bounded load (≤12 workers, ≤400 req, ≤35s)
                with explicit consent — proves rate limits without multi-IP flooding.
              </p>
            </article>
          </div>
          <p className="section-sub" style={{ marginTop: "1.5rem" }}>
            Multi-region / multi-IP capacity tests belong in your cloud with k6 during a change
            window. Bastionscan will not open-proxy botnet-style DDoS — that would make the
            platform a weapon for black hats.
          </p>
        </div>
      </section>
    </main>
  );
}
