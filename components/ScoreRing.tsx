interface ScoreRingProps {
  score: number;
  size?: number;
  stroke?: number;
  label?: string;
  sublabel?: string;
}

function colorFor(score: number): string {
  if (score >= 90) return "#22c55e";
  if (score >= 80) return "#84cc16";
  if (score >= 70) return "#eab308";
  if (score >= 55) return "#f97316";
  return "#ef4444";
}

export default function ScoreRing({
  score,
  size = 132,
  stroke = 11,
  label,
  sublabel,
}: ScoreRingProps) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const dash = (pct / 100) * c;
  const color = colorFor(score);

  return (
    <div className="ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={stroke}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c - dash}`}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dasharray 0.9s cubic-bezier(0.22,1,0.36,1)" }}
        />
      </svg>
      <div className="ring-center">
        <span className="ring-label" style={{ color }}>
          {label ?? pct}
        </span>
        {sublabel && <span className="ring-sub">{sublabel}</span>}
      </div>
    </div>
  );
}
