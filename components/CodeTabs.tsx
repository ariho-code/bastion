"use client";

import { useState } from "react";

export interface CodeSample {
  label: string;
  code: string;
}

export default function CodeTabs({ samples }: { samples: CodeSample[] }) {
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(samples[active].code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="ct">
      <div className="ct-bar">
        <div className="ct-tabs" role="tablist">
          {samples.map((s, i) => (
            <button
              key={s.label}
              role="tab"
              aria-selected={i === active}
              className={`ct-tab ${i === active ? "on" : ""}`}
              onClick={() => setActive(i)}
            >
              {s.label}
            </button>
          ))}
        </div>
        <button className="ct-copy" onClick={copy} aria-label="Copy code">
          {copied ? "Copied ✓" : "Copy"}
        </button>
      </div>
      <pre className="ct-pre">
        <code>{samples[active].code}</code>
      </pre>
    </div>
  );
}
