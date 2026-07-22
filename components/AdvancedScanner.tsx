"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import UpgradeModal from "./UpgradeModal";
import { isPro, getQuota, bumpQuota, syncProFromURL, FREE_ADVANCED_LIMIT } from "@/lib/pro";
import { downloadAdvancedReport } from "@/lib/advancedPdf";

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

interface CVEMatch {
  product: string;
  version: string;
  fixed_in: string;
  severity: Severity;
  cves: string[];
  summary: string;
  source?: string; // "curated" or "osv" (live feed)
  url?: string; // advisory link (OSV)
}

interface ScamVerdict {
  verdict: string; // SAFE / LOW RISK / SUSPICIOUS / DANGEROUS
  level: number; // 0..3
  is_scam: boolean;
  brand?: string | null;
  headline: string;
  reasons: string[];
  advice: string;
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
  cve_matches: CVEMatch[];
  remediation: RemediationItem[];
  scam?: ScamVerdict | null;
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
  verified: boolean;
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

interface VerifyRecord {
  domain: string;
  record: string;
  instruction: string;
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
  const [profile, setProfile] = useState<"standard" | "deep" | "active">("deep");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(0);
  const [data, setData] = useState<AssessResponse | null>(null);
  const [error, setError] = useState("");
  const [verify, setVerify] = useState<VerifyRecord | null>(null);
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [pro, setPro] = useState(false);
  const [remaining, setRemaining] = useState(FREE_ADVANCED_LIMIT);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalReason, setModalReason] = useState<string | undefined>(undefined);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshEntitlement = useCallback(() => {
    setPro(isPro());
    setRemaining(Math.max(0, FREE_ADVANCED_LIMIT - getQuota("advanced")));
  }, []);

  const openUpgrade = useCallback((reason?: string) => {
    setModalReason(reason);
    setModalOpen(true);
  }, []);

  const getVerify = useCallback(async () => {
    const t = target.trim();
    if (!t || verifyLoading) return;
    setVerifyLoading(true);
    setVerify(null);
    try {
      const res = await fetch(`/api/verify?target=${encodeURIComponent(t)}`);
      const json = await res.json();
      if (res.ok) setVerify(json as VerifyRecord);
    } finally {
      setVerifyLoading(false);
    }
  }, [target, verifyLoading]);

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
    async (rawTarget?: string, rawProfile?: "standard" | "deep" | "active") => {
      const t = (rawTarget ?? target).trim();
      const p = rawProfile ?? profile;
      if (!t || loading) return;

      // Pro gating (bypassed for Pro / ?pro=1). Active is Pro-only; free users
      // also get a generous daily allowance of deep scans.
      if (!isPro()) {
        if (p === "active") {
          openUpgrade(
            "Active scanning — intrusive, ownership-verified checks like HTTP-method probing and content discovery — is a Pro capability."
          );
          return;
        }
        if (getQuota("advanced") >= FREE_ADVANCED_LIMIT) {
          openUpgrade(
            `You've used all ${FREE_ADVANCED_LIMIT} free advanced scans today. Upgrade to Pro for unlimited deep & active scans.`
          );
          return;
        }
      }

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
        bumpQuota("advanced");
        refreshEntitlement();
      } catch (e) {
        setError(e instanceof Error ? e.message : "Scan failed.");
      } finally {
        setLoading(false);
      }
    },
    [target, profile, loading, openUpgrade, refreshEntitlement]
  );

  // Deep-linkable scans: /advanced?target=example.com&profile=deep auto-runs.
  useEffect(() => {
    syncProFromURL();
    refreshEntitlement();
    const params = new URLSearchParams(window.location.search);
    const t = params.get("target");
    if (!t) return;
    const raw = params.get("profile");
    const p: "standard" | "deep" | "active" =
      raw === "standard" ? "standard" : raw === "active" ? "active" : "deep";
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
          {(["standard", "deep", "active"] as const).map((p) => (
            <button
              key={p}
              type="button"
              role="tab"
              aria-selected={profile === p}
              className={`av-profile-btn ${profile === p ? "on" : ""}`}
              onClick={() => setProfile(p)}
            >
              {p === "standard" ? "Standard" : p === "deep" ? "Deep" : "Active"}
              {p === "active" && !pro && <span className="av-pro-tag">PRO</span>}
            </button>
          ))}
        </div>
        <button className="av-run" type="submit" disabled={loading}>
          {loading ? "Scanning…" : "Run scan"}
        </button>
      </form>

      {!pro && (
        <div className="av-quota">
          <span>
            {remaining > 0
              ? `${remaining} of ${FREE_ADVANCED_LIMIT} free advanced scans left today`
              : "You've used your free advanced scans for today"}
          </span>
          <button type="button" className="av-quota-link" onClick={() => openUpgrade(undefined)}>
            Go Pro — unlimited + active scans
          </button>
        </div>
      )}

      {profile === "active" && !pro && (
        <div className="av-pro-note">
          <div className="av-pro-note-body">
            <span className="av-pro-note-badge">★ PRO</span>
            <div>
              <strong>Active scanning is a Pro capability.</strong> It runs intrusive,
              ownership-verified checks — HTTP-method probing, content discovery and more — against
              domains you control.
            </div>
          </div>
          <button type="button" className="av-pro-btn" onClick={() => openUpgrade("Unlock active scanning with Pro.")}>
            Unlock Pro
          </button>
        </div>
      )}

      {profile === "active" && pro && (
        <div className="av-verify">
          <p className="av-verify-lede">
            <strong>Active scans are ownership-gated.</strong> They run intrusive checks (HTTP method
            probing and more), so they only unlock for domains you prove you control. Publish this DNS
            TXT record, then scan.
          </p>
          <button type="button" className="av-verify-btn" onClick={getVerify} disabled={verifyLoading}>
            {verifyLoading ? "Fetching…" : "Get verification record"}
          </button>
          {verify && (
            <div className="av-verify-rec">
              <div className="av-verify-row">
                <span>Host</span>
                <code>{verify.domain}</code>
              </div>
              <div className="av-verify-row">
                <span>Type</span>
                <code>TXT</code>
              </div>
              <div className="av-verify-row">
                <span>Value</span>
                <code>{verify.record}</code>
              </div>
              <p className="av-verify-hint">{verify.instruction}</p>
            </div>
          )}
        </div>
      )}

      {loading && (
        <div className="av-loading">
          <div className="av-spinner" />
          <span>{STAGES[stage]}</span>
        </div>
      )}

      {error && !data && <div className="av-error">{error}</div>}

      {data && !loading && <Report data={data} pro={pro} onUpgrade={openUpgrade} />}

      <UpgradeModal open={modalOpen} onClose={() => setModalOpen(false)} plan="Pro" reason={modalReason} />
    </div>
  );
}

// --- report -----------------------------------------------------------------

function Report({
  data,
  pro,
  onUpgrade,
}: {
  data: AssessResponse;
  pro: boolean;
  onUpgrade: (reason?: string) => void;
}) {
  const { scan, analysis } = data;
  const level = analysis.risk_level;
  const color = riskColor(level);

  const [company, setCompany] = useState("");
  const [downloading, setDownloading] = useState(false);

  // Load any saved white-label company name (Pro).
  useEffect(() => {
    try {
      setCompany(localStorage.getItem("bastion:whitelabel") || "");
    } catch {
      /* noop */
    }
  }, []);

  const onCompanyChange = (v: string) => {
    setCompany(v);
    try {
      localStorage.setItem("bastion:whitelabel", v);
    } catch {
      /* noop */
    }
  };

  const download = useCallback(async () => {
    if (!pro) {
      onUpgrade("White-label PDF reports — branded with your own company name — are a Pro feature.");
      return;
    }
    setDownloading(true);
    try {
      await downloadAdvancedReport(data, { company: company.trim() });
    } finally {
      setDownloading(false);
    }
  }, [pro, onUpgrade, data, company]);

  const surface = useMemo(
    () => scan.findings.filter((f) => f.category === "surface"),
    [scan.findings]
  );
  const intel = useMemo(
    () => scan.findings.filter((f) => f.category === "intel"),
    [scan.findings]
  );
  const content = useMemo(
    () => scan.findings.filter((f) => f.category === "content"),
    [scan.findings]
  );
  const ranModules = scan.modules.filter((m) => !m.skipped);

  return (
    <div className="av-report">
      {/* scam & phishing verdict — the first thing a person should see */}
      {analysis.scam && <ScamBanner scam={analysis.scam} />}

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
            {scan.profile === "active" && (
              <span className={`av-vchip ${scan.verified ? "ok" : "no"}`}>
                {scan.verified ? "Ownership verified ✓" : "Unverified — active checks skipped"}
              </span>
            )}
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

      {/* export / white-label report */}
      <section className="av-export">
        <div className="av-export-main">
          <button className="av-export-btn" onClick={download} disabled={downloading}>
            {downloading ? "Preparing…" : "Download report (PDF)"}
            {!pro && <span className="av-pro-tag">PRO</span>}
          </button>
          <span className="av-export-hint">
            {pro
              ? "Executive risk report — grade, CVEs, category risk, and the full remediation roadmap."
              : "White-label PDF reports, branded with your own company name, are a Pro feature."}
          </span>
        </div>
        {pro && (
          <input
            className="av-export-input"
            value={company}
            onChange={(e) => onCompanyChange(e.target.value)}
            placeholder="Your company name (optional, white-label)"
            aria-label="White-label company name"
            spellCheck={false}
            maxLength={48}
          />
        )}
      </section>

      {/* known vulnerabilities (CVE correlation) */}
      {analysis.cve_matches.length > 0 && (
        <section className="av-card">
          <h4 className="av-card-title">
            Known vulnerabilities
            {analysis.cve_matches.some((m) => m.source === "osv") && (
              <span className="av-livefeed" title="Enriched with the live OSV.dev advisory feed">
                ● live feed
              </span>
            )}
          </h4>
          <div className="av-cve-list">
            {analysis.cve_matches.map((m, i) => (
              <div className="av-cve-item" key={i}>
                <span
                  className="av-chip"
                  style={{ color: sevColor(m.severity), borderColor: sevColor(m.severity) }}
                >
                  {m.severity}
                </span>
                <div className="av-cve-body">
                  <div className="av-cve-head">
                    <strong>
                      {m.product} {m.version}
                    </strong>
                    <span className="av-cve-fix">→ upgrade to {m.fixed_in}+</span>
                    {m.source === "osv" && <span className="av-live">LIVE</span>}
                  </div>
                  <p className="av-cve-detail">{m.summary}</p>
                  <div className="av-cve-ids">
                    {m.cves.map((c) =>
                      m.url ? (
                        <a
                          className="av-cve-id av-cve-link"
                          href={m.url}
                          target="_blank"
                          rel="noreferrer"
                          key={c}
                        >
                          {c} ↗
                        </a>
                      ) : (
                        <span className="av-cve-id" key={c}>
                          {c}
                        </span>
                      )
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

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

      {/* signals: attack surface + content integrity + threat intel */}
      <div className="av-grid">
        {surface.length > 0 && (
          <section className="av-card">
            <h4 className="av-card-title">Attack surface</h4>
            <SignalList findings={surface} />
          </section>
        )}
        {content.length > 0 && (
          <section className="av-card">
            <h4 className="av-card-title">Content integrity</h4>
            <SignalList findings={content} />
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

// scamStyle maps a 0..3 scam level to a color, background tint and icon.
function scamStyle(level: number): { color: string; bg: string; border: string; icon: string } {
  switch (level) {
    case 3:
      return { color: "#ef4444", bg: "rgba(239,68,68,0.10)", border: "rgba(239,68,68,0.45)", icon: "⛔" };
    case 2:
      return { color: "#f97316", bg: "rgba(249,115,22,0.10)", border: "rgba(249,115,22,0.45)", icon: "⚠️" };
    case 1:
      return { color: "#eab308", bg: "rgba(234,179,8,0.10)", border: "rgba(234,179,8,0.40)", icon: "⚠️" };
    default:
      return { color: "#22c55e", bg: "rgba(34,197,94,0.10)", border: "rgba(34,197,94,0.40)", icon: "✅" };
  }
}

function ScamBanner({ scam }: { scam: ScamVerdict }) {
  const s = scamStyle(scam.level);
  return (
    <section
      className="av-scam"
      role={scam.is_scam ? "alert" : undefined}
      style={{ background: s.bg, borderColor: s.border }}
    >
      <div className="av-scam-head">
        <span className="av-scam-icon" aria-hidden="true">
          {s.icon}
        </span>
        <div>
          <div className="av-scam-verdict" style={{ color: s.color }}>
            {scam.verdict}
            {scam.brand ? <span className="av-scam-brand"> · impersonates {scam.brand}</span> : null}
          </div>
          <p className="av-scam-headline">{scam.headline}</p>
        </div>
      </div>
      <p className="av-scam-advice" style={{ color: s.color }}>
        {scam.advice}
      </p>
      {scam.reasons.length > 0 && (
        <ul className="av-scam-reasons">
          {scam.reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      )}
    </section>
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
