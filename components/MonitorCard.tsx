"use client";

import { useState } from "react";
import Icon from "./Icon";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function MonitorCard({ host }: { host: string }) {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [msg, setMsg] = useState("");

  async function subscribe() {
    const to = email.trim().toLowerCase();
    if (!EMAIL_RE.test(to)) {
      setState("error");
      setMsg("Please enter a valid email address.");
      return;
    }
    setState("loading");
    setMsg("");
    try {
      const r = await fetch("/api/monitor", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: host, email: to }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || "Couldn't enable monitoring.");
      setState("done");
      setMsg(`We'll re-scan ${host} daily and alert you the moment its grade drops.`);
    } catch (e: any) {
      setState("error");
      setMsg(e?.message || "Couldn't enable monitoring.");
    }
  }

  return (
    <div className="email-capture monitor-capture">
      <div className="email-capture-text">
        <span className="email-capture-title">
          <Icon name="bell" size={16} /> Monitor {host} automatically
        </span>
        <span className="email-capture-sub">
          Daily re-scans with an instant email alert if the security grade ever drops.
        </span>
      </div>
      {state === "done" ? (
        <div className="email-done">
          <Icon name="check" size={17} /> {msg}
        </div>
      ) : (
        <div className="email-form">
          <input
            className="email-input"
            type="email"
            inputMode="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && subscribe()}
            autoCapitalize="none"
            autoCorrect="off"
            aria-label="Email for monitoring alerts"
          />
          <button className="email-btn" onClick={subscribe} disabled={state === "loading"}>
            {state === "loading" ? <span className="spinner" /> : "Monitor daily"}
          </button>
        </div>
      )}
      {state === "error" && (
        <div className="email-error" style={{ width: "100%" }}>
          {msg}
        </div>
      )}
    </div>
  );
}
