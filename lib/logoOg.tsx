import {
  B_MONOGRAM,
  MONOGRAM_FILL,
  SHIELD_GRADIENT_ID,
  SHIELD_GRADIENT_STOPS,
  shieldPathD,
} from "./logoMark";

/** Renders the shield mark as raw SVG JSX for next/og ImageResponse (Satori) contexts. */
export function shieldSvg(size: number) {
  const pad = size * 0.18;
  const inner = size - pad * 2;
  const scale = inner / 56;
  const shieldW = 48 * scale;
  const shieldH = 56 * scale;
  const offsetX = pad + (inner - shieldW) / 2;
  const offsetY = pad + (inner - shieldH) / 2;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <defs>
        <linearGradient id={SHIELD_GRADIENT_ID} x1="0" y1="0" x2="1" y2="1">
          {SHIELD_GRADIENT_STOPS.map((s) => (
            <stop key={s.offset} offset={s.offset} stopColor={s.color} />
          ))}
        </linearGradient>
      </defs>
      <g transform={`translate(${offsetX},${offsetY}) scale(${scale})`}>
        <path d={shieldPathD()} fill={`url(#${SHIELD_GRADIENT_ID})`} />
        {B_MONOGRAM.map((r, i) => (
          <rect key={i} x={r.x} y={r.y} width={r.width} height={r.height} rx={r.rx} fill={MONOGRAM_FILL} />
        ))}
      </g>
    </svg>
  );
}
