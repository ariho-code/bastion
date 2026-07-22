/**
 * Single source of truth for the Bastionscan shield mark.
 * A crenellated (castle-top) shield with a bold rounded "B" monogram,
 * defined as plain geometry so it can be rendered identically by:
 *  - components/Logo.tsx        (inline SVG in the browser)
 *  - app/brand/icon/route.tsx   (favicon / apple-icon / manifest PNGs via next/og)
 *  - app/brand/logo-email/route.tsx (hosted PNG for email clients)
 *  - app/og/route.tsx, app/opengraph-image.tsx (social share images)
 *  - lib/pdf.ts                 (native jsPDF vector shapes, no image embed)
 */

export const SHIELD_VIEWBOX = "0 0 48 56";

/** Absolute (x,y) points of the shield outline, straight edges only (renders identically as SVG path or jsPDF polyline). */
export const SHIELD_POLYGON: [number, number][] = [
  [4, 11],
  [4, 4],
  [12, 4],
  [12, 11],
  [20, 11],
  [20, 4],
  [28, 4],
  [28, 11],
  [36, 11],
  [36, 4],
  [44, 4],
  [44, 11],
  [44, 26],
  [24, 54],
  [4, 26],
];

/** Rounded-rect segments that compose the "B" monogram — maps 1:1 to SVG <rect rx> and jsPDF roundedRect(). */
export const B_MONOGRAM = [
  { x: 17, y: 16, width: 5, height: 24, rx: 2 },
  { x: 19, y: 16, width: 10, height: 11, rx: 5.5 },
  { x: 19, y: 28, width: 11, height: 12, rx: 6 },
] as const;

export const SHIELD_GRADIENT_ID = "bastionShieldGrad";
export const SHIELD_GRADIENT_STOPS: { offset: number; color: string }[] = [
  { offset: 0, color: "#3b82f6" },
  { offset: 1, color: "#1d4ed8" },
];
export const SHIELD_GRADIENT_RGB: [[number, number, number], [number, number, number]] = [
  [59, 130, 246],
  [29, 78, 216],
];
/** Flat mid-tone fallback for renderers that can't do gradients (e.g. jsPDF solid fill). */
export const SHIELD_SOLID_RGB: [number, number, number] = [37, 99, 235];

export const MONOGRAM_FILL = "#ffffff";

export const WORDMARK_DARK = "#0b1220"; // "Bastion" on light backgrounds
export const WORDMARK_LIGHT = "#f5f8fc"; // "Bastion" on dark backgrounds
export const WORDMARK_ACCENT = "#2563eb"; // "scan"

export const MOTTO = "SECURE TODAY. PROTECT TOMORROW.";

/** Display size (CSS px) for the hosted email logo <img> — the PNG is rendered at EMAIL_LOGO_SCALE for retina. */
export const EMAIL_LOGO_WIDTH = 200;
export const EMAIL_LOGO_HEIGHT = 48;
export const EMAIL_LOGO_SCALE = 3;

/** Builds an SVG path `d` string from the closed shield polygon. */
export function shieldPathD(): string {
  const [first, ...rest] = SHIELD_POLYGON;
  return `M${first[0]},${first[1]} ` + rest.map(([x, y]) => `L${x},${y}`).join(" ") + " Z";
}
