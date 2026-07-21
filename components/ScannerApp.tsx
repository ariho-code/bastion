"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { ScanResult, Finding, Category } from "@/lib/scanner/types";
import { brand } from "@/lib/brand";
import { downloadReport } from "@/lib/pdf";
import ScoreRing from "./ScoreRing";

const EXAMPLES = ["github.com", "stripe.com", "wikipedia.org"];

const CATEGORY_BLURB: Record<Category, string> = {
  transport: "HTTPS, redirects, HSTS & TLS certificate",
  headers: "CSP, clickjacking, MIME & referrer controls",
  dns: "Email spoofing protection & certificate authority rules",
  cookies: "Secure, HttpOnly & SameSite flags",
  disclosure: "Server banners, methods & disclosure policy",
};

const LOADING_STAGES = [
  "Resolving DNS…",
  "Negotiating TLS handshake…",
  "Fetching response headers…",
  "Checking email & certificate records…",
  "Scoring findings…",
];

function gradeColor(grade: string): string {
  return (
    { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" }[grade] || "#94a3b8"
  );
}

interface HistoryItem {
  host: string;
  grade: string;
  score: number;
  at: number;
}

export default function ScannerApp() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState(0);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [copied, setCopied] = useState<string>("");
  const resultRef = useRef<HTMLDivElement>(null);

  // Load history
  useEffect(() => {
    try {
      const raw = localStorage.getItem("bastion:history");
      if (raw) setHistory(JSON.parse(raw));
    } catch {
      /* noop */
    }
  }, []);

  // Deep-link: ?url=example.com auto-runs a scan
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const q = params.get("url");
    if (q) {
      setUrl(q);
      void runScan(q);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Cycle loading stages
  useEffect(() => {
    if (!loading) return;
    setStage(0);
    const id = setInterval(() => setStage((s) => Math.min(s + 1, LOADING_STAGES.length - 1)), 900);
    return () => clearInterval(id);
  }, [loading]);

  const saveHistory = useCallback((r: ScanResult) => {
    setHistory((prev) => {
      const next = [
        { host: r.host, grade: r.grade, score: r.score, at: Date.now() },
        ...prev.filter((h) => h.host !== r.host),
      ].slice(0, 6);
      try {
        localStorage.setItem("bastion:history", JSON.stringify(next));
      } catch {
        /* noop */
      }
      return next;
    });
  }, []);

  const runScan = useCallback(
    async (target?: string) => {
      const t = (target ?? url).trim();
      if (!t || loading) return;
      if (target) setUrl(target);
      setLoading(true);
      setError("");
      setResult(null);
      setOpen({});
      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: t }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Scan failed. Please try again.");
        setResult(data as ScanResult);
        saveHistory(data as ScanResult);
        setTimeout(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
      } catch (e: any) {
        setError(e?.message || "Something went wrong.");
      } finally {
        setLoading(false);
      }
    },
    [url, loading, saveHistory]
  );

  function upgrade(plan: string) {
    if (brand.checkoutUrl) {
      window.open(brand.checkoutUrl, "_blank", "noopener");
    } else {
      alert(
        `${plan} is launching soon. Add your checkout link in lib/brand.ts (Lemon Squeezy / Paddle / Polar) to accept payments.`
      );
    }
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(""), 1600);
    } catch {
      /* noop */
    }
  }

  async function shareLink() {
    if (!result) return;
    const link = `${window.location.origin}/?url=${encodeURIComponent(result.host)}&grade=${encodeURIComponent(
      result.grade
    )}&score=${result.score}`;
    // Native share sheet on mobile (bigger reach), copy-to-clipboard elsewhere.
    const nav = navigator as Navigator & { share?: (data: ShareData) => Promise<void> };
    if (nav.share && /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) {
      try {
        await nav.share({
          title: `${result.host} scored ${result.grade} on ${brand.name}`,
          text: `${result.host} scored a security grade of ${result.grade} (${result.score}/100) on ${brand.name}. Check any site free:`,
          url: link,
        });
        return;
      } catch {
        /* user cancelled or unsupported — fall back to copy */
      }
    }
    copy(link, "share");
  }

  const counts = result
    ? { pass: result.passed, warn: result.warnings, fail: result.failed }
    : null;

  return (
    <>
      <div className="scan-shell" id="scan">
        <div className="scan-box">
          <span className="scan-lock" aria-hidden="true">
            🔒
          </span>
          <input
            className="scan-input"
            type="text"
            inputMode="url"
            placeholder="Enter a website, e.g. yourcompany.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runScan()}
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
            aria-label="Website URL to scan"
          />
          <button className="scan-btn" onClick={() => runScan()} disabled={loading}>
            {loading ? <span className="spinner" /> : "Scan now"}
          </button>
        </div>

        <div className="examples">
          <span className="examples-label">Try one:</span>
          {EXAMPLES.map((ex) => (
            <button key={ex} className="example-chip" onClick={() => runScan(ex)} disabled={loading}>
              {ex}
            </button>
          ))}
        </div>

        {!result && !loading && history.length > 0 && (
          <div className="history">
            <span className="history-label">Recent</span>
            {history.map((h) => (
              <button key={h.host} className="history-chip" onClick={() => runScan(h.host)}>
                <span className="history-grade" style={{ color: gradeColor(h.grade) }}>
                  {h.grade}
                </span>
                {h.host}
              </button>
            ))}
          </div>
        )}

        {error && (
          <div className="error" role="alert">
            <strong>Couldn&apos;t scan.</strong> {error}
          </div>
        )}
      </div>

      {loading && (
        <div className="loading-card">
          <div className="scanbeam" />
          <div className="loading-text">
            <span className="spinner dark" />
            {LOADING_STAGES[stage]}
          </div>
        </div>
      )}

      {result && counts && (
        <section className="result" ref={resultRef} aria-live="polite">
          {/* Grade + summary */}
          <div className="grade-card">
            <ScoreRing score={result.score} label={result.grade} sublabel={`${result.score}/100`} />
            <div className="grade-meta">
              <h2 className="grade-host">{result.host}</h2>
              <div className="pills">
                <span className="pill pill-pass">{counts.pass} passed</span>
                <span className="pill pill-warn">{counts.warn} warnings</span>
                <span className="pill pill-fail">{counts.fail} failed</span>
              </div>
              <div className="chips">
                {result.meta.ip && <span className="chip">IP {result.meta.ip}</span>}
                {result.meta.tls?.protocol && <span className="chip">{result.meta.tls.protocol}</span>}
                {typeof result.meta.tls?.daysRemaining === "number" && (
                  <span className="chip">cert {result.meta.tls.daysRemaining}d left</span>
                )}
                <span className={`chip ${result.meta.email?.spf ? "chip-ok" : "chip-bad"}`}>
                  SPF {result.meta.email?.spf ? "✓" : "✗"}
                </span>
                <span className={`chip ${result.meta.email?.dmarc ? "chip-ok" : "chip-bad"}`}>
                  DMARC {result.meta.email?.dmarc ? "✓" : "✗"}
                </span>
                {result.meta.server && <span className="chip">{result.meta.server}</span>}
              </div>
              <div className="actions">
                <button className="act act-primary" onClick={() => downloadReport(result)}>
                  ⬇ Download PDF report
                </button>
                <button className="act" onClick={shareLink}>
                  {copied === "share" ? "Link copied ✓" : "🔗 Share result"}
                </button>
                <button className="act" onClick={() => runScan(result.host)}>
                  ↻ Re-scan
                </button>
              </div>
            </div>
          </div>

          {/* Category breakdown */}
          <div className="cats">
            {result.categories.map((c) => (
              <div className="cat" key={c.category}>
                <ScoreRing score={c.score} size={78} stroke={7} sublabel="" />
                <div className="cat-info">
                  <div className="cat-name">{c.label}</div>
                  <div className="cat-blurb">{CATEGORY_BLURB[c.category]}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Findings */}
          <div className="findings">
            <div className="findings-head">
              <h3>Findings</h3>
              <span className="findings-sub">{result.findings.length} checks · sorted by priority</span>
            </div>
            {result.findings.map((f) => (
              <FindingRow
                key={f.id}
                f={f}
                open={!!open[f.id]}
                onToggle={() => setOpen((o) => ({ ...o, [f.id]: !o[f.id] }))}
                onCopyFix={(fix) => copy(fix, f.id)}
                copied={copied === f.id}
              />
            ))}
          </div>

          {/* Conversion band */}
          <div className="upsell">
            <div className="upsell-text">
              <strong>Keep {result.host} secure — automatically.</strong>
              <span>
                {brand.name} Pro re-scans your sites on a schedule, emails you the moment a grade drops,
                and exports white-label reports for clients.
              </span>
            </div>
            <button className="upsell-btn" onClick={() => upgrade("Pro")}>
              Start monitoring →
            </button>
          </div>
        </section>
      )}
    </>
  );
}

function FindingRow({
  f,
  open,
  onToggle,
  onCopyFix,
  copied,
}: {
  f: Finding;
  open: boolean;
  onToggle: () => void;
  onCopyFix: (fix: string) => void;
  copied: boolean;
}) {
  return (
    <div className={`finding finding-${f.status}`}>
      <button className="finding-head" onClick={onToggle} aria-expanded={open}>
        <span className={`dot dot-${f.status}`} />
        <span className="finding-title">{f.title}</span>
        <span className={`sev sev-${f.severity}`}>{f.severity}</span>
        {f.maxPoints > 0 && (
          <span className="finding-pts">
            {f.points}/{f.maxPoints}
          </span>
        )}
        <span className="chev">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="finding-body">
          <p>{f.detail}</p>
          {f.evidence && <div className="evidence">{f.evidence}</div>}
          {f.fix && (
            <div className="fix">
              <div className="fix-top">
                <span className="fix-label">Recommended fix</span>
                <button className="copy-fix" onClick={() => onCopyFix(f.fix!)}>
                  {copied ? "Copied ✓" : "Copy"}
                </button>
              </div>
              <pre className="code">{f.fix}</pre>
            </div>
          )}
          {f.reference && (
            <a className="ref" href={f.reference} target="_blank" rel="noreferrer noopener">
              Reference documentation ↗
            </a>
          )}
        </div>
      )}
    </div>
  );
}
