"use client";

import { useState } from "react";
import UpgradeModal from "./UpgradeModal";
import T from "./T";

interface Tier {
  name: string;
  monthly: number;
  annual: number; // per-month equivalent
  tagline: string;
  features: string[];
  cta: string;
  featured?: boolean;
  plan: string;
}

const TIERS: Tier[] = [
  {
    name: "Free",
    monthly: 0,
    annual: 0,
    tagline: "Everything you need to check and fix a site.",
    features: [
      "Unlimited security scans",
      "Full A–F grade across all 28 checks",
      "Copy-paste fix for every issue",
      "PDF report export",
      "Local scan history",
    ],
    cta: "Scan a site",
    plan: "Free",
  },
  {
    name: "Pro",
    monthly: 9,
    annual: 7,
    tagline: "Stay secure automatically, across all your sites.",
    features: [
      "Everything in Free",
      "Continuous monitoring & daily re-scans",
      "Email alerts the moment a grade drops",
      "Bulk scan up to 25 sites",
      "Cloud history & score trends",
      "Remove Bastion branding from PDFs",
    ],
    cta: "Go Pro",
    featured: true,
    plan: "Pro",
  },
  {
    name: "Agency",
    monthly: 29,
    annual: 24,
    tagline: "For teams and consultants securing clients at scale.",
    features: [
      "Everything in Pro",
      "Unlimited sites & team members",
      "Full white-label reports (your logo)",
      "REST API access",
      "Scheduled client email reports",
      "Priority support",
    ],
    cta: "Start Agency",
    plan: "Agency",
  },
];

export default function Pricing() {
  const [annual, setAnnual] = useState(true);
  const [modalPlan, setModalPlan] = useState<string | null>(null);

  function choose(tier: Tier) {
    if (tier.monthly === 0) {
      document.getElementById("scan")?.scrollIntoView({ behavior: "smooth" });
      return;
    }
    setModalPlan(tier.plan);
  }

  return (
    <section id="pricing" className="pricing">
      <div className="section-head">
        <span className="eyebrow">
          <T k="price.eyebrow" />
        </span>
        <h2>
          <T k="price.title" />
        </h2>
        <p>
          <T k="price.sub" />
        </p>
      </div>

      <div className="toggle" role="group" aria-label="Billing period">
        <button className={!annual ? "toggle-on" : ""} onClick={() => setAnnual(false)}>
          Monthly
        </button>
        <button className={annual ? "toggle-on" : ""} onClick={() => setAnnual(true)}>
          Annual <span className="save">save 2 months</span>
        </button>
      </div>

      <div className="tiers">
        {TIERS.map((t) => {
          const price = annual ? t.annual : t.monthly;
          return (
            <div key={t.name} className={`tier ${t.featured ? "tier-featured" : ""}`}>
              {t.featured && <div className="tier-tag">Most popular</div>}
              <div className="tier-name">{t.name}</div>
              <div className="tier-price">
                {price === 0 ? (
                  <span className="free">Free</span>
                ) : (
                  <>
                    <span className="cur">$</span>
                    {price}
                    <span className="per">/mo</span>
                  </>
                )}
              </div>
              <div className="tier-billed">
                {price === 0
                  ? "forever"
                  : annual
                  ? `billed $${t.annual * 12}/year`
                  : "billed monthly · cancel anytime"}
              </div>
              <p className="tier-tagline">{t.tagline}</p>
              <ul>
                {t.features.map((f) => (
                  <li key={f}>
                    <span className="tick">✓</span>
                    {f}
                  </li>
                ))}
              </ul>
              <button
                className={`tier-btn ${t.featured ? "" : "ghost"}`}
                onClick={() => choose(t)}
              >
                {t.cta}
              </button>
            </div>
          );
        })}
      </div>
      <p className="pricing-foot">
        Prices in USD. Payments handled by our merchant of record — local cards, PayPal, Apple Pay &amp;
        Google Pay supported worldwide. 14-day money-back guarantee on paid plans.
      </p>

      <UpgradeModal
        open={!!modalPlan}
        onClose={() => setModalPlan(null)}
        plan={modalPlan || "Pro"}
      />
    </section>
  );
}
