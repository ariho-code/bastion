"use client";

import { useCallback, useEffect, useState } from "react";

interface VerifyRecord {
  domain: string;
  record: string;
  instruction: string;
}

/**
 * Lightweight enterprise workbench: verify ownership, craft scope, jump into
 * Advanced Active with pre-filled query params for a full DAST run.
 */
export default function EnterpriseConsole() {
  const [target, setTarget] = useState("");
  const [exclude, setExclude] = useState("/billing\n/admin/production");
  const [disable, setDisable] = useState("");
  const [vertical, setVertical] = useState("banking");
  const [verify, setVerify] = useState<VerifyRecord | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<
    { id: string; target: string; grade: string; risk_level: string; vertical: string; profile: string }[]
  >([]);

  useEffect(() => {
    fetch("/api/history?limit=12")
      .then((r) => r.json())
      .then((d) => setHistory(d.scans || []))
      .catch(() => setHistory([]));
  }, []);

  const getVerify = useCallback(async () => {
    const t = target.trim();
    if (!t) {
      setError("Enter a hostname you own.");
      return;
    }
    setLoading(true);
    setError("");
    setVerify(null);
    try {
      const res = await fetch(`/api/verify?target=${encodeURIComponent(t)}`);
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error || json?.detail || "Verify failed");
      setVerify(json as VerifyRecord);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verify failed");
    } finally {
      setLoading(false);
    }
  }, [target]);

  const launchActive = () => {
    const t = target.trim();
    if (!t) {
      setError("Enter a hostname you own.");
      return;
    }
    const params = new URLSearchParams({ target: t, profile: "active" });
    // Scope is applied in AdvancedScanner session; store hint for operators.
    if (typeof window !== "undefined") {
      try {
        sessionStorage.setItem(
          "bastion.enterprise.scope",
          JSON.stringify({
            excludePaths: exclude.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
            disableModules: disable.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
            vertical,
          })
        );
      } catch {
        /* ignore */
      }
    }
    window.location.href = `/advanced?${params.toString()}`;
  };

  return (
    <section className="ec card" style={{ marginTop: "1.25rem" }}>
      <h2 style={{ fontFamily: "var(--display)", letterSpacing: "-0.02em" }}>Workbench</h2>
      <div className="ec-row">
        <input
          className="ec-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="yourcompany.com"
          aria-label="Owned domain"
        />
        <button type="button" className="ec-btn" onClick={getVerify} disabled={loading}>
          {loading ? "…" : "1. Get DNS verify record"}
        </button>
        <button type="button" className="ec-btn primary" onClick={launchActive}>
          2. Launch Active DAST
        </button>
      </div>
      {error && <p className="ec-err">{error}</p>}
      {verify && (
        <div className="ec-verify">
          <p>
            Publish a TXT record on <code>{verify.domain}</code>:
          </p>
          <code className="ec-token">{verify.record}</code>
          <p className="ec-hint">{verify.instruction}</p>
        </div>
      )}
      <div className="ec-scope">
        <label>
          Industry vertical
          <select value={vertical} onChange={(e) => setVertical(e.target.value)}>
            <option value="banking">Banking / fintech</option>
            <option value="ecommerce">E-commerce</option>
            <option value="saas">SaaS / B2B</option>
            <option value="scam">Anti-fraud / scam kit cleanup</option>
            <option value="general">General</option>
          </select>
        </label>
        <label>
          Exclude paths (one per line)
          <textarea value={exclude} onChange={(e) => setExclude(e.target.value)} rows={3} />
        </label>
        <label>
          Disable modules (comma-separated)
          <input
            value={disable}
            onChange={(e) => setDisable(e.target.value)}
            placeholder="authweak, discovery"
          />
        </label>
      </div>
      {history.length > 0 && (
        <div className="ec-hist">
          <h3>Recent scans (learning history)</h3>
          <ul>
            {history.map((h) => (
              <li key={h.id}>
                <code>{h.target}</code> · {h.profile} · {h.vertical} · grade {h.grade} · {h.risk_level}
              </li>
            ))}
          </ul>
        </div>
      )}
      <style>{`
        .ec {
          background: rgba(15, 23, 42, 0.7);
          border: 1px solid rgba(148, 163, 184, 0.18);
          border-radius: 16px;
          padding: 1.25rem 1.35rem 1.5rem;
          margin: 1.5rem 0 2rem;
        }
        .ec h2 { margin: 0 0 1rem; font-size: 1.1rem; }
        .ec-row { display: flex; flex-wrap: wrap; gap: 0.6rem; }
        .ec-input {
          flex: 1 1 200px; min-width: 180px; background: #0b1220;
          border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 10px;
          color: #e2e8f0; padding: 0.65rem 0.8rem;
        }
        .ec-btn {
          border-radius: 10px; border: 1px solid rgba(148, 163, 184, 0.3);
          background: transparent; color: #e2e8f0; padding: 0.6rem 0.9rem;
          font-weight: 600; cursor: pointer;
        }
        .ec-btn.primary { background: linear-gradient(135deg, #2563eb, #7c3aed); border-color: transparent; }
        .ec-err { color: #f87171; margin: 0.75rem 0 0; }
        .ec-verify {
          margin-top: 1rem; padding: 0.9rem; border-radius: 12px;
          background: rgba(34, 197, 94, 0.08); border: 1px solid rgba(34, 197, 94, 0.25);
        }
        .ec-token { display: block; word-break: break-all; margin: 0.5rem 0; color: #86efac; }
        .ec-hint { margin: 0; font-size: 0.85rem; color: #94a3b8; }
        .ec-scope { display: grid; gap: 0.75rem; margin-top: 1rem; }
        .ec-scope label { display: flex; flex-direction: column; gap: 0.35rem; font-size: 0.85rem; color: #94a3b8; }
        .ec-scope textarea, .ec-scope input, .ec-scope select {
          background: #0b1220; border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 10px;
          color: #e2e8f0; padding: 0.55rem 0.7rem; font-family: ui-monospace, monospace; font-size: 0.85rem;
        }
        .ec-hist { margin-top: 1.25rem; }
        .ec-hist h3 { font-size: 0.95rem; margin: 0 0 0.5rem; }
        .ec-hist ul { margin: 0; padding-left: 1.1rem; color: #94a3b8; font-size: 0.85rem; line-height: 1.6; }
      `}</style>
    </section>
  );
}
