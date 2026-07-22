"use client";

import { useCallback, useRef, useState } from "react";

// A deliberately simple, non-technical surface: paste a link, get a clear
// verdict. It reuses the full engine + risk brain via /api/deep, but hides all
// the security jargon and shows only what a person needs: is this safe, why,
// and what to do.

interface ScamVerdict {
  verdict: string; // SAFE / LOW RISK / SUSPICIOUS / DANGEROUS
  level: number; // 0..3
  is_scam: boolean;
  brand?: string | null;
  headline: string;
  reasons: string[];
  advice: string;
}

interface Finding {
  id: string;
  detail: string;
  evidence?: string;
}

interface DeepResponse {
  scan?: { host?: string; findings?: Finding[] };
  analysis?: { scam?: ScamVerdict | null };
  error?: string;
}

interface Result {
  host: string;
  scam: ScamVerdict;
  ageLine: string;
}

function levelStyle(level: number): { color: string; bg: string; border: string; icon: string; ring: string } {
  switch (level) {
    case 3:
      return { color: "#ef4444", bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.5)", icon: "⛔", ring: "rgba(239,68,68,0.25)" };
    case 2:
      return { color: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.5)", icon: "⚠️", ring: "rgba(249,115,22,0.25)" };
    case 1:
      return { color: "#eab308", bg: "rgba(234,179,8,0.10)", border: "rgba(234,179,8,0.45)", icon: "⚠️", ring: "rgba(234,179,8,0.22)" };
    default:
      return { color: "#22c55e", bg: "rgba(34,197,94,0.10)", border: "rgba(34,197,94,0.45)", icon: "✅", ring: "rgba(34,197,94,0.22)" };
  }
}

export default function ScamCheck() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const check = useCallback(async () => {
    const value = target.trim();
    if (!value) {
      setError("Paste a website link to check.");
      inputRef.current?.focus();
      return;
    }
    setLoading(true);
    setError("");
    setResult(null);
    try {
      // Deep profile: full phishing + reputation + lexical + infra signals.
      const res = await fetch("/api/deep", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target: value, profile: "deep" }),
      });
      const data: DeepResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || "We couldn't check that link right now. Please try again.");
      }
      const scam = data.analysis?.scam;
      if (!scam) {
        throw new Error("We couldn't produce a verdict for that link. Try a full address like https://example.com.");
      }
      const findings = data.scan?.findings ?? [];
      const rep = findings.find((f) => f.id === "phishing.reputation");
      const ageLine = rep?.evidence ? rep.evidence : "";
      setResult({ host: data.scan?.host || value, scam, ageLine });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [target]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") check();
  };

  return (
    <div className="sc">
      <div className="sc-form">
        <input
          ref={inputRef}
          className="sc-input"
          type="text"
          inputMode="url"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          placeholder="Paste a link, e.g. paypa1-login.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={onKey}
          disabled={loading}
          aria-label="Website link to check for scams"
        />
        <button className="sc-btn" onClick={check} disabled={loading}>
          {loading ? "Checking…" : "Check now"}
        </button>
      </div>
      <p className="sc-hint">
        Free. We never store the link. Works for shopping sites, crypto/wallet links, banking &amp;
        mobile-money pages, and more.
      </p>

      {error && (
        <div className="sc-error" role="alert">
          {error}
        </div>
      )}

      {loading && (
        <div className="sc-loading" aria-live="polite">
          <span className="sc-spinner" aria-hidden="true" />
          Running a deep multi-signal scan — domain age, blocklists, naming patterns, hosting, and page content…
        </div>
      )}

      {result && <Verdict result={result} />}
    </div>
  );
}

function Verdict({ result }: { result: Result }) {
  const s = levelStyle(result.scam.level);
  const { scam } = result;
  return (
    <section
      className="sc-result"
      role={scam.is_scam ? "alert" : undefined}
      style={{ background: s.bg, borderColor: s.border, boxShadow: `0 0 0 4px ${s.ring}` }}
    >
      <div className="sc-verdict-row">
        <span className="sc-verdict-icon" aria-hidden="true">
          {s.icon}
        </span>
        <div>
          <div className="sc-verdict" style={{ color: s.color }}>
            {scam.verdict}
          </div>
          <div className="sc-host">{result.host}</div>
        </div>
      </div>

      <p className="sc-headline">{scam.headline}</p>

      <div className="sc-advice" style={{ borderColor: s.border }}>
        <strong style={{ color: s.color }}>What to do:</strong> {scam.advice}
      </div>

      {scam.brand && (
        <p className="sc-brand">
          This site appears to imitate <strong>{scam.brand}</strong>. Reach {scam.brand} only by
          typing its real address yourself.
        </p>
      )}

      {scam.reasons.length > 0 && (
        <div className="sc-reasons">
          <div className="sc-reasons-h">Why we flagged this</div>
          <ul>
            {scam.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {result.ageLine && <p className="sc-age">{result.ageLine}</p>}

      <p className="sc-more">
        Want the full technical breakdown (TLS, headers, exposure, CVEs)?{" "}
        <a href="/advanced">Run an advanced scan →</a>
      </p>
    </section>
  );
}
