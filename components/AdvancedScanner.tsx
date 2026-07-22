"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// --- types (mirror the brain's /v1/assess response) -------------------------

type Status = "pass" | "warn" | "fail" | "info";
type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  id: string;
  module: string;
  category: string;
  title: string;
  status: Status;
  severity: Severity;
  points: number;
  maxPoints: number;
  detail: string;
  fix?: string;
  reference?: string;
  evidence?: string;
}

interface CategoryRisk {
  category: string;
  label: string;
  risk: number;
  open_issues: number;
}

interface RemediationItem {
  priority: string;
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  fix?: string;
  reference?: string;
  effort: string;
  points_lost: number;
}

interface Analysis {
  target: string;
  grade: string;
  score: number;
  risk_index: number;
  risk_level: string;
  headline: string;
  summary: string[];
  strengths: string[];
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  category_risk: CategoryRisk[];
  remediation: RemediationItem[];
}

interface ModuleRun {
  id: string;
  durationMs: number;
  findings: number;
  skipped?: boolean;
}

interface Scan {
  host: string;
  domain: string;
  profile: string;
  grade: string;
  score: number;
  findings: Finding[];
  modules: ModuleRun[];
  passed: number;
  warnings: number;
  failed: number;
  durationMs: number;
}

interface AssessResponse {
  scan: Scan;
  analysis: Analysis;
}

// --- helpers ----------------------------------------------------------------

const STAGES = [
  "Resolving target & network…",
  "Negotiating TLS handshakes…",
  "Mapping attack surface…",
  "Probing exposed endpoints…",
  "Correlating threat intelligence…",
  "Scoring risk & prioritizing fixes…",
];

function riskColor(level: string): string {
  return (
    {
      Critical: "#ef4444",
      High: "#f97316",
      Medium: "#eab308",
      Low: "#84cc16",
      Minimal: "#22c55e",
    }[level] || "#22d3ee"
  );
}

function sevColor(sev: Severity): string {
  return (
    {
      critical: "#ef4444",
      high: "#f97316",
      medium: "#eab308",
      low: "#84cc16",
      info: "#647689",
    }[sev] || "#647689"
  );
}

function statusColor(s: Status): string {
  return { pass: "#22c55e", warn: "#eab308", fail: "#ef4444", info: "#647689" }[s];
}

function gradeColor(grade: string): string {
  return (
    { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" }[grade] || "#94a3b8"
  );
}

// --- component --------------------------------------------------------------

export default function AdvancedScanner() {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState<"standard" | "deep">("deep");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(0);
  const [data, setData] = useState<AssessResponse | null>(null);
  const [error, setError] = useState("");
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (loading) {
      setStage(0);
      timer.current = setInterval(() => setStage((s) => (s + 1) % STAGES.length), 1400);
    } else if (timer.current) {
      clearInterval(timer.current);
    }
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [loading]);

  const run = useCallback(
    async (rawTarget?: string, rawProfile?: "standard" | "deep") => {
      const t = (rawTarget ?? target).trim();
      const p = rawProfile ?? profile;
      if (!t || loading) return;
      setLoading(true);
      setError("");
      setData(null);
      try {
        const res = await fetch("/api/deep", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ target: t, profile: p }),
        });
        const json = await res.json();
        if (!res.ok) throw new Error(json?.error || "Scan failed.");
        setData(json as AssessResponse);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Scan failed.");
      } finally {
        setLoading(false);
      }
    },
    [target, profile, loading]
  );

  // Deep-linkable scans: /advanced?target=example.com&profile=deep auto-runs.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const t = params.get("target");
    if (!t) return;
    const p = params.get("profile") === "standard" ? "standard" : "deep";
    setTarget(t);
    setProfile(p);
    run(t, p);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="av">
      <form
        className="av-form"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <input
          className="av-input"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="example.com"
          aria-label="Target to scan"
          autoComplete="off"
          spellCheck={false}
        />
        <div className="av-profile" role="tablist" aria-label="Scan depth">
          {(["standard", "deep"] as const).map((p) => (
            <button
              key={p}
              type="button"
              role="tab"
              aria-selected={profile === p}
              className={`av-profile-btn ${profile === p ? "on" : ""}`}
              onClick={() => setProfile(p)}
            >
              {p === "standard" ? "Standard" : "Deep"}
            </button>
          ))}
        </div>
        <button className="av-run" type="submit" disabled={loading}>
          {loading ? "Scanning…" : "Run deep scan"}
        </button>
      </form>

      {loading && (
        <div className="av-loading">
          <div className="av-spinner" />
          <span>{STAGES[stage]}</span>
        </div>
      )}

      {error && <div className="av-error">{error}</div>}

      {data && !loading && <Report data={data} />}
    </div>
  );
}

// --- report -----------------------------------------------------------------

function Report({ data }: { data: AssessResponse }) {
  const { scan, analysis } = data;
  const level = analysis.risk_level;
  const color = riskColor(level);

  const surface = useMemo(
    () => scan.findings.filter((f) => f.category === "surface"),
    [scan.findings]
  );
  const intel = useMemo(
    () => scan.findings.filter((f) => f.category === "intel"),
    [scan.findings]
  );
  const ranModules = scan.modules.filter((m) => !m.skipped);

  return (
    <div className="av-report">
      {/* hero */}
      <section className="av-hero">
        <Gauge value={analysis.risk_index} color={color} />
        <div className="av-hero-main">
          <div className="av-hero-top">
            <span className="av-grade" style={{ background: gradeColor(scan.grade), color: "#04070c" }}>
              {scan.grade}
            </span>
            <span className="av-level" style={{ color }}>
              {level} risk
            </span>
            <span className="av-host">{scan.host}</span>
          </div>
          <h3 className="av-headline">{analysis.headline}</h3>
          <ul className="av-summary">
            {analysis.summary.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
          <div className="av-sev-row">
            <SevPill label="Critical" n={analysis.critical_count} c="#ef4444" />
            <SevPill label="High" n={analysis.high_count} c="#f97316" />
            <SevPill label="Medium" n={analysis.medium_count} c="#eab308" />
            <SevPill label="Low" n={analysis.low_count} c="#84cc16" />
          </div>
          <div className="av-meta">
            {ranModules.length} modules · {scan.passed} passed · {scan.warnings} warnings ·{" "}
            {scan.failed} failed · {(scan.durationMs / 1000).toFixed(1)}s
          </div>
        </div>
      </section>

      {/* category risk */}
      {analysis.category_risk.length > 0 && (
        <section className="av-card">
          <h4 className="av-card-title">Risk by category</h4>
          <div className="av-bars">
            {analysis.category_risk.map((c) => (
              <div className="av-bar-row" key={c.category}>
                <span className="av-bar-label">{c.label}</span>
                <div className="av-bar-track">
                  <div
                    className="av-bar-fill"
                    style={{ width: `${c.risk}%`, background: riskGradient(c.risk) }}
                  />
                </div>
                <span className="av-bar-val">{c.risk}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* remediation */}
      {analysis.remediation.length > 0 && (
        <section className="av-card">
          <h4 className="av-card-title">Prioritized remediation</h4>
          <div className="av-rem">
            {analysis.remediation.map((r, i) => (
              <div className="av-rem-item" key={i}>
                <span className="av-prio" data-p={r.priority}>
                  {r.priority}
                </span>
                <div className="av-rem-body">
                  <div className="av-rem-head">
                    <strong>{r.title}</strong>
                    <span className="av-chip" style={{ color: sevColor(r.severity), borderColor: sevColor(r.severity) }}>
                      {r.severity}
                    </span>
                    <span className="av-effort">{r.effort}</span>
                    {r.points_lost > 0 && <span className="av-pts">+{r.points_lost} pts</span>}
                  </div>
                  <p className="av-rem-detail">{r.detail}</p>
                  {r.fix && <p className="av-fix">→ {r.fix}</p>}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* signals: attack surface + threat intel */}
      <div className="av-grid">
        {surface.length > 0 && (
          <section className="av-card">
            <h4 className="av-card-title">Attack surface</h4>
            <SignalList findings={surface} />
          </section>
        )}
        {intel.length > 0 && (
          <section className="av-card">
            <h4 className="av-card-title">Threat intelligence</h4>
            <SignalList findings={intel} />
          </section>
        )}
      </div>

      {/* strengths */}
      {analysis.strengths.length > 0 && (
        <section className="av-card">
          <h4 className="av-card-title">What&apos;s working well</h4>
          <div className="av-strengths">
            {analysis.strengths.map((s) => (
              <span className="av-strength" key={s}>
                ✓ {s}
              </span>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function SignalList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="av-signals">
      {findings.map((f) => (
        <li key={f.id}>
          <span className="av-dot" style={{ background: statusColor(f.status) }} />
          <div>
            <div className="av-signal-title">{f.title}</div>
            <div className="av-signal-detail">{f.evidence || f.detail}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function SevPill({ label, n, c }: { label: string; n: number; c: string }) {
  return (
    <span className={`av-sevpill ${n > 0 ? "hot" : ""}`} style={n > 0 ? { borderColor: c, color: c } : {}}>
      <b>{n}</b> {label}
    </span>
  );
}

function Gauge({ value, color }: { value: number; color: string }) {
  const r = 52;
  const circ = 2 * Math.PI * r;
  const [shown, setShown] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setShown(value));
    return () => cancelAnimationFrame(id);
  }, [value]);
  const offset = circ * (1 - shown / 100);
  return (
    <div className="av-gauge">
      <svg viewBox="0 0 128 128" width="128" height="128">
        <circle cx="64" cy="64" r={r} fill="none" stroke="#1c2735" strokeWidth="11" />
        <circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="11"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 64 64)"
          style={{ transition: "stroke-dashoffset 1s cubic-bezier(.4,0,.2,1)" }}
        />
      </svg>
      <div className="av-gauge-center">
        <span className="av-gauge-num" style={{ color }}>
          {Math.round(shown)}
        </span>
        <span className="av-gauge-cap">risk index</span>
      </div>
    </div>
  );
}

function riskGradient(v: number): string {
  if (v >= 70) return "linear-gradient(90deg,#f97316,#ef4444)";
  if (v >= 40) return "linear-gradient(90deg,#eab308,#f97316)";
  if (v >= 15) return "linear-gradient(90deg,#84cc16,#eab308)";
  return "linear-gradient(90deg,#22c55e,#84cc16)";
}
