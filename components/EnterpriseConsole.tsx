"use client";

import { useCallback, useEffect, useState } from "react";
import Icon from "@/components/Icon";

interface VerifyRecord {
  domain: string;
  record: string;
  instruction: string;
}

interface HistoryRow {
  id: string;
  target: string;
  grade: string;
  risk_level: string;
  vertical: string;
  profile: string;
}

/**
 * Enterprise workbench — verify ownership, set scope, launch Advanced Active.
 * Styled with the same design tokens as the marketing homepage.
 */
export default function EnterpriseConsole() {
  const [target, setTarget] = useState("");
  const [exclude, setExclude] = useState("/billing\n/admin/production");
  const [disable, setDisable] = useState("");
  const [vertical, setVertical] = useState("banking");
  const [intensity, setIntensity] = useState("safe");
  const [verify, setVerify] = useState<VerifyRecord | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState<HistoryRow[]>([]);

  useEffect(() => {
    fetch("/api/history?limit=8")
      .then((r) => r.json())
      .then((d) => setHistory(Array.isArray(d.scans) ? d.scans : []))
      .catch(() => setHistory([]));
  }, []);

  const getVerify = useCallback(async () => {
    const t = target.trim();
    if (!t) {
      setError("Enter a domain you own.");
      return;
    }
    setLoading(true);
    setError("");
    setVerify(null);
    try {
      const res = await fetch(`/api/verify?target=${encodeURIComponent(t)}`);
      const json = await res.json();
      if (!res.ok) throw new Error(json?.error || json?.detail || "Could not create a verify record.");
      setVerify(json as VerifyRecord);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create a verify record.");
    } finally {
      setLoading(false);
    }
  }, [target]);

  const copyRecord = async () => {
    if (!verify?.record) return;
    try {
      await navigator.clipboard.writeText(verify.record);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignore */
    }
  };

  const launchActive = () => {
    const t = target.trim();
    if (!t) {
      setError("Enter a domain you own.");
      return;
    }
    const params = new URLSearchParams({ target: t, profile: "active" });
    try {
      sessionStorage.setItem(
        "bastion.enterprise.scope",
        JSON.stringify({
          excludePaths: exclude.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
          disableModules: disable.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
          vertical,
          intensity,
        })
      );
    } catch {
      /* ignore */
    }
    window.location.href = `/advanced?${params.toString()}`;
  };

  return (
    <div className="wb">
      <div className="wb-shell">
        {/* Step 1 — target */}
        <div className="wb-panel">
          <div className="wb-step-head">
            <span className="wb-step-n">1</span>
            <div>
              <h3>Your domain</h3>
              <p>Only domains you control. Active checks stay locked until DNS proves ownership.</p>
            </div>
          </div>
          <div className="wb-row">
            <input
              className="wb-input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && getVerify()}
              placeholder="yourcompany.com"
              aria-label="Domain you own"
              spellCheck={false}
            />
            <button type="button" className="wb-btn" onClick={getVerify} disabled={loading}>
              {loading ? "Working…" : "Get verify record"}
            </button>
          </div>
          {error && <p className="wb-err">{error}</p>}
          {verify && (
            <div className="wb-verify">
              <div className="wb-verify-top">
                <span className="wb-verify-ok">
                  <Icon name="check" size={14} /> Ready to publish
                </span>
                <button type="button" className="wb-copy" onClick={copyRecord}>
                  {copied ? "Copied" : "Copy record"}
                </button>
              </div>
              <p className="wb-verify-label">
                Add a <strong>TXT</strong> record on <code>{verify.domain}</code>
              </p>
              <code className="wb-token">{verify.record}</code>
              <p className="wb-hint">
                After DNS propagates (often a few minutes), launch Active. We check the record
                ourselves — nothing is trusted from the browser alone.
              </p>
            </div>
          )}
        </div>

        {/* Step 2 — scope */}
        <div className="wb-panel">
          <div className="wb-step-head">
            <span className="wb-step-n">2</span>
            <div>
              <h3>Scope &amp; focus</h3>
              <p>Tell us what to leave alone and how deep this run should go.</p>
            </div>
          </div>
          <div className="wb-grid">
            <label className="wb-field">
              <span>Industry focus</span>
              <select value={vertical} onChange={(e) => setVertical(e.target.value)}>
                <option value="banking">Banking / fintech</option>
                <option value="ecommerce">E-commerce</option>
                <option value="saas">SaaS / B2B</option>
                <option value="scam">Anti-fraud</option>
                <option value="general">General</option>
              </select>
            </label>
            <label className="wb-field">
              <span>How thorough</span>
              <select value={intensity} onChange={(e) => setIntensity(e.target.value)}>
                <option value="safe">Safe — everyday monitoring</option>
                <option value="thorough">Thorough — pre-release review</option>
                <option value="aggressive">Aggressive — change window</option>
              </select>
            </label>
            <label className="wb-field wb-field-wide">
              <span>Do not test these paths</span>
              <textarea
                value={exclude}
                onChange={(e) => setExclude(e.target.value)}
                rows={3}
                placeholder={"/billing\n/admin/production"}
                spellCheck={false}
              />
            </label>
            <label className="wb-field wb-field-wide">
              <span>Skip optional checks (optional)</span>
              <input
                value={disable}
                onChange={(e) => setDisable(e.target.value)}
                placeholder="e.g. leave blank for full coverage"
                spellCheck={false}
              />
            </label>
          </div>
        </div>

        {/* Step 3 — launch */}
        <div className="wb-panel wb-panel-launch">
          <div className="wb-step-head">
            <span className="wb-step-n">3</span>
            <div>
              <h3>Launch</h3>
              <p>Opens Advanced with your scope applied. Publish the DNS record first for full Active coverage.</p>
            </div>
          </div>
          <button type="button" className="wb-launch" onClick={launchActive}>
            Launch Active scan
            <Icon name="arrow-right" size={18} />
          </button>
        </div>
      </div>

      {history.length > 0 && (
        <div className="wb-history">
          <div className="wb-history-head">
            <h3>Recent activity</h3>
            <span>Saved on your account space</span>
          </div>
          <div className="wb-history-table">
            {history.map((h) => (
              <div className="wb-history-row" key={h.id}>
                <span className="wb-h-host">{h.target}</span>
                <span className={`wb-h-grade g-${(h.grade || "").toLowerCase()}`}>{h.grade || "—"}</span>
                <span className="wb-h-meta">{h.risk_level || "—"}</span>
                <span className="wb-h-meta">{h.vertical || "general"}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
