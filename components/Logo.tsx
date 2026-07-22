import {
  B_MONOGRAM,
  MONOGRAM_FILL,
  MOTTO,
  SHIELD_GRADIENT_ID,
  SHIELD_GRADIENT_STOPS,
  SHIELD_VIEWBOX,
  WORDMARK_ACCENT,
  WORDMARK_LIGHT,
  shieldPathD,
} from "@/lib/logoMark";

interface LogoProps {
  /** "mark" = shield only. "full" = shield + wordmark inline. "stacked" = shield + wordmark + motto, centered. */
  variant?: "mark" | "full" | "stacked";
  size?: number;
  className?: string;
  animated?: boolean;
}

/** The Bastionscan shield mark — crenellated shield + rounded "B" monogram, gradient-filled. */
export function ShieldMark({
  size = 28,
  className,
  animated = false,
  gradientId,
}: {
  size?: number;
  className?: string;
  animated?: boolean;
  gradientId?: string;
}) {
  const gid = gradientId || SHIELD_GRADIENT_ID;
  return (
    <svg
      width={size}
      height={size}
      viewBox={SHIELD_VIEWBOX}
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          {SHIELD_GRADIENT_STOPS.map((s) => (
            <stop key={s.offset} offset={s.offset} stopColor={s.color} />
          ))}
        </linearGradient>
      </defs>
      <path
        d={shieldPathD()}
        fill={`url(#${gid})`}
        className={animated ? "shield-pulse" : undefined}
      />
      {B_MONOGRAM.map((r, i) => (
        <rect
          key={i}
          x={r.x}
          y={r.y}
          width={r.width}
          height={r.height}
          rx={r.rx}
          fill={MONOGRAM_FILL}
        />
      ))}
    </svg>
  );
}

/** Full lockup: shield + "Bastion" + "scan" wordmark, with an optional motto for stacked use. */
export default function Logo({ variant = "full", size = 28, className, animated = false }: LogoProps) {
  if (variant === "mark") {
    return <ShieldMark size={size} className={className} animated={animated} />;
  }

  const stacked = variant === "stacked";

  return (
    <span className={`logo-lockup ${stacked ? "logo-lockup-stacked" : ""} ${className || ""}`}>
      <ShieldMark size={size} animated={animated} />
      <span className="logo-word">
        <span style={{ color: WORDMARK_LIGHT }}>Bastion</span>
        <span style={{ color: WORDMARK_ACCENT }}>scan</span>
      </span>
      {stacked && <span className="logo-motto">{MOTTO}</span>}
    </span>
  );
}
