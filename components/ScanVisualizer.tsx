"use client";

import Icon, { type IconName } from "./Icon";
import { ShieldMark } from "./Logo";

const CATEGORY_ICONS: { icon: IconName; label: string }[] = [
  { icon: "lock", label: "Transport" },
  { icon: "shield", label: "Headers" },
  { icon: "mail", label: "DNS & Email" },
  { icon: "cookie", label: "Cookies" },
  { icon: "file-text", label: "Content" },
  { icon: "eye", label: "Disclosure" },
];

interface ScanVisualizerProps {
  stages: string[];
  stage: number;
  host?: string;
}

/** Live "scan in progress" visualization: pulsing shield radar, category sweep, terminal-style log. */
export default function ScanVisualizer({ stages, stage, host }: ScanVisualizerProps) {
  const lit = Math.min(
    CATEGORY_ICONS.length,
    Math.round(((stage + 1) / stages.length) * CATEGORY_ICONS.length)
  );

  return (
    <div className="scanviz" role="status" aria-live="polite">
      <div className="scanviz-top">
        <div className="scanviz-radar">
          <span className="radar-ring r1" />
          <span className="radar-ring r2" />
          <span className="radar-ring r3" />
          <ShieldMark size={36} animated />
        </div>
        <div className="scanviz-headline">
          <span className="scanviz-eyebrow">Scanning{host ? ` ${host}` : ""}…</span>
          <span className="scanviz-sub">Live security analysis in progress</span>
        </div>
      </div>

      <div className="scanviz-cats">
        {CATEGORY_ICONS.map((c, i) => (
          <span
            key={c.label}
            className={`scanviz-cat${i < lit ? " cat-lit" : ""}${i === lit - 1 ? " cat-active" : ""}`}
          >
            <Icon name={c.icon} size={13} />
            {c.label}
          </span>
        ))}
      </div>

      <div className="scanviz-terminal">
        {stages.map((s, i) => {
          const state = i < stage ? "term-done" : i === stage ? "term-active" : "term-pending";
          return (
            <div key={s} className={`term-line ${state}`}>
              <span className="term-glyph">{i < stage ? "✓" : i === stage ? ">" : "·"}</span>
              <span>{s}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
