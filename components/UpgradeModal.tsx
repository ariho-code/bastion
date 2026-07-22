"use client";

import { useEffect, useState } from "react";
import { brand } from "@/lib/brand";
import Icon, { type IconName } from "./Icon";

const BENEFITS: { icon: IconName; text: string }[] = [
  { icon: "users", text: "Bulk-scan your entire portfolio in one click" },
  { icon: "file-text", text: "White-label PDF reports with your own logo" },
  { icon: "activity", text: "Cloud history & score trends over time" },
  { icon: "code", text: "Higher API rate limits for CI/CD at scale" },
  { icon: "bell", text: "Priority support & onboarding" },
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function UpgradeModal({
  open,
  onClose,
  plan = "Pro",
  reason,
}: {
  open: boolean;
  onClose: () => void;
  plan?: string;
  reason?: string;
}) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [open, onClose]);

  if (!open) return null;

  async function submit() {
    // Real checkout configured → send them straight to it.
    if (brand.checkoutUrl) {
      window.open(brand.checkoutUrl, "_blank", "noopener");
      return;
    }
    // Otherwise capture the lead onto the waitlist.
    if (!EMAIL_RE.test(email)) {
      setState("error");
      setMsg("Please enter a valid email address.");
      return;
    }
    setState("loading");
    try {
      const r = await fetch("/api/lead", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, plan }),
      });
      if (!r.ok) throw new Error();
      setState("done");
      setMsg("You're on the list — we'll email you the moment it launches.");
    } catch {
      setState("error");
      setMsg(`Couldn't sign you up. Email us at ${brand.contactEmail}.`);
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose} aria-label="Close">
          <Icon name="x" size={18} />
        </button>

        <div className="modal-badge">
          <Icon name="sparkles" size={14} /> {brand.name} {plan}
        </div>
        <h3 className="modal-title">
          {reason || `Unlock ${plan} to secure every site, automatically.`}
        </h3>
        <p className="modal-sub">
          Free covers one-off checks. {plan} keeps your whole portfolio at an A — hands-off.
        </p>

        <ul className="modal-benefits">
          {BENEFITS.map((b) => (
            <li key={b.text}>
              <span className="modal-benefit-icon">
                <Icon name={b.icon} size={15} />
              </span>
              {b.text}
            </li>
          ))}
        </ul>

        {state === "done" ? (
          <div className="modal-success">
            <Icon name="check" size={18} /> {msg}
          </div>
        ) : brand.checkoutUrl ? (
          <button className="modal-cta" onClick={submit}>
            Upgrade to {plan} <Icon name="arrow-right" size={17} />
          </button>
        ) : (
          <>
            <div className="modal-form">
              <input
                className="modal-input"
                type="email"
                inputMode="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submit()}
                autoCapitalize="none"
                autoCorrect="off"
              />
              <button className="modal-cta" onClick={submit} disabled={state === "loading"}>
                {state === "loading" ? (
                  <span className="spinner" />
                ) : (
                  <>
                    Get early access <Icon name="arrow-right" size={17} />
                  </>
                )}
              </button>
            </div>
            {state === "error" && <div className="modal-msg modal-msg-error">{msg}</div>}
          </>
        )}

        <div className="modal-foot">
          <Icon name="lock" size={13} /> No spam. Priced fairly — cancel anytime.
        </div>
      </div>
    </div>
  );
}
