import type { Metadata } from "next";
import Link from "next/link";
import { brand } from "@/lib/brand";
import EnterpriseConsole from "@/components/EnterpriseConsole";
import Icon, { type IconName } from "@/components/Icon";

export const metadata: Metadata = {
  title: `Enterprise security · ${brand.name}`,
  description:
    "Ownership-verified security testing for production teams — scoped Active checks, clear reports, and a security advisor that stays plain-spoken.",
};

const CAPS: { icon: IconName; title: string; body: string }[] = [
  {
    icon: "shield-check",
    title: "Prove you own it first",
    body: "Deep, intrusive checks only unlock after a DNS record proves control of the domain. No spoofing from the browser.",
  },
  {
    icon: "zap",
    title: "Real attack paths, safely",
    body: "Injection, scripting flaws, weak cookies, open admin surfaces, and more — reported with clear fixes, not raw exploit kits.",
  },
  {
    icon: "activity",
    title: "Quiet or thorough",
    body: "Start gentle for daily monitoring. Step up intensity in a change window when you need a harder look at your defenses.",
  },
  {
    icon: "gauge",
    title: "You set the boundaries",
    body: "Exclude payment rails, partner APIs, or fragile admin paths. Only test what you allow — safe defaults out of the box.",
  },
  {
    icon: "sparkles",
    title: "A clear security advisor",
    body: "Plain-language priorities after every scan. Mark issues that look wrong so future reports stay sharper for your team.",
  },
  {
    icon: "code",
    title: "Ship with a grade gate",
    body: "Run the same checks in CI and fail the build when security posture slips. Repeatable, auditable, pipeline-ready.",
  },
];

const INTENSITY: { tier: string; label: string; body: string; tag: string }[] = [
  {
    tier: "01",
    label: "Safe",
    tag: "Default",
    body: "Light, precise checks for everyday monitoring. Ideal when you need evidence without noise.",
  },
  {
    tier: "02",
    label: "Thorough",
    tag: "Recommended for reviews",
    body: "Broader coverage and quieter probing patterns — good for validating edge protections before a release.",
  },
  {
    tier: "03",
    label: "Aggressive",
    tag: "Change window only",
    body: "Highest authorized budget for domains you own. Optional short load check stays hard-capped and path-scoped.",
  },
];

export default function EnterprisePage() {
  return (
    <main>
      {/* Hero — same system as homepage */}
      <section className="hero">
        <div className="hero-bg" aria-hidden="true">
          <div className="hero-aurora" />
          <div className="hero-grid" />
          <div className="hero-scan" />
          <div className="hero-vignette" />
        </div>
        <div className="hero-inner">
          <div className="badge">
            <span className="badge-dot" />
            Enterprise · ownership-verified testing
          </div>
          <h1>
            Find the hole first.
            <br />
            <span className="grad">Keep production standing.</span>
          </h1>
          <p className="hero-sub">
            Built for marketplaces, banks, SaaS, and product orgs that need attacker-grade coverage
            on systems they own — with hard boundaries, plain reports, and no drama for your
            customers.
          </p>
          <div className="hero-trust">
            <span>DNS-verified Active</span>
            <span className="sep" />
            <span>Scoped exclusions</span>
            <span className="sep" />
            <span>CI-ready grade gates</span>
          </div>
          <div className="ent-hero-actions">
            <a href="#console" className="final-btn ent-hero-btn">
              Open workbench →
            </a>
            <Link href="/advanced?profile=active" className="act ent-hero-secondary">
              Go to Advanced
            </Link>
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section className="features" id="capabilities">
        <div className="section-head">
          <span className="eyebrow">Why teams choose us</span>
          <h2>Security that matches how you ship</h2>
          <p>
            Same problem at every scale: find issues before someone else does — without taking the
            site down to do it.
          </p>
        </div>
        <div className="feature-grid">
          {CAPS.map((c) => (
            <article key={c.title} className="feature">
              <div className="feature-icon" aria-hidden="true">
                <Icon name={c.icon} size={22} />
              </div>
              <h3>{c.title}</h3>
              <p>{c.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Workbench */}
      <section className="capabilities" id="console">
        <div className="section-head">
          <span className="eyebrow">Workbench</span>
          <h2>Verify, scope, and launch</h2>
          <p>
            Prove ownership, set what must not be touched, choose how thorough the run should be —
            then open a full Active scan with those settings applied.
          </p>
        </div>
        <EnterpriseConsole />
      </section>

      {/* Intensity */}
      <section className="how" id="intensity">
        <div className="section-head">
          <span className="eyebrow">Depth</span>
          <h2>Three levels. One rule: stay in bounds.</h2>
          <p>
            Pick the intensity that fits your change window. Aggressive never leaves the paths and
            limits you set.
          </p>
        </div>
        <div className="steps ent-intensity">
          {INTENSITY.map((s) => (
            <div key={s.label} className="step">
              <div className="step-n">{s.tier}</div>
              <div className="ent-tier-tag">{s.tag}</div>
              <h3>{s.label}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
        <p className="ent-footnote">
          Heavy multi-region capacity tests still belong in your own cloud during a planned window.
          We keep hard caps so this product can never be used as a flood weapon.
        </p>
      </section>

      {/* CTA */}
      <section className="final-cta">
        <div className="final-inner">
          <h2>Ready to test what you own?</h2>
          <p>
            Start with a free public scan, or open the workbench when you&apos;re ready for
            ownership-verified Active checks.
          </p>
          <div className="ent-cta-row">
            <a href="#console" className="final-btn">
              Open workbench →
            </a>
            <Link href="/" className="ent-cta-link">
              Free public scan
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
