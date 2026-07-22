import { ImageResponse } from "next/og";
import type { NextRequest } from "next/server";
import { brand } from "@/lib/brand";
import { shieldSvg } from "@/lib/logoOg";

export const runtime = "edge";

const GRADE_COLORS: Record<string, string> = {
  A: "#22c55e",
  B: "#84cc16",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
};

/**
 * Dynamic Open Graph image for shared scan results.
 * GET /og?host=example.com&grade=A&score=95
 * Rendered into the share card so a result looks premium on
 * Twitter/X, LinkedIn, Slack, iMessage, etc. — the viral loop.
 */
export function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const host = (searchParams.get("host") || brand.domainSuggestion).slice(0, 64);
  const grade = (searchParams.get("grade") || "A").toUpperCase().slice(0, 1);
  const score = (searchParams.get("score") || "").replace(/[^0-9]/g, "").slice(0, 3);
  const color = GRADE_COLORS[grade] || "#94a3b8";

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#0a0e14",
          padding: "64px 72px",
          fontFamily: "sans-serif",
        }}
      >
        {/* Brand row */}
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {shieldSvg(44)}
          <div style={{ display: "flex", fontSize: 36, fontWeight: 700 }}>
            <span style={{ color: "#e6edf3" }}>Bastion</span>
            <span style={{ color: "#3b82f6" }}>scan</span>
          </div>
          <div
            style={{
              marginLeft: 14,
              fontSize: 22,
              color: "#5f6f82",
              display: "flex",
              alignItems: "center",
            }}
          >
            Website Security Report
          </div>
        </div>

        {/* Grade + host */}
        <div style={{ display: "flex", alignItems: "center", gap: 44 }}>
          <div
            style={{
              width: 240,
              height: 240,
              borderRadius: 36,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 150,
              fontWeight: 800,
              color: "#0a0e14",
              background: color,
              boxShadow: `0 0 90px -10px ${color}`,
            }}
          >
            {grade}
          </div>
          <div style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 28, color: "#93a1b3", display: "flex" }}>Security grade for</div>
            <div
              style={{
                fontSize: 58,
                color: "#ffffff",
                fontWeight: 800,
                lineHeight: 1.1,
                display: "flex",
                overflow: "hidden",
              }}
            >
              {host}
            </div>
            {score ? (
              <div style={{ fontSize: 34, color: color, fontWeight: 700, marginTop: 10, display: "flex" }}>
                {score}/100
              </div>
            ) : (
              <div style={{ display: "flex" }} />
            )}
          </div>
        </div>

        {/* Footer strip */}
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {["A", "B", "C", "D", "F"].map((g, i) => (
            <div
              key={g}
              style={{
                width: 52,
                height: 52,
                borderRadius: 12,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 28,
                fontWeight: 800,
                color: "#0a0e14",
                opacity: g === grade ? 1 : 0.28,
                background: ["#22c55e", "#84cc16", "#eab308", "#f97316", "#ef4444"][i],
              }}
            >
              {g}
            </div>
          ))}
          <div style={{ flex: 1 }} />
          <div style={{ fontSize: 26, color: "#93a1b3", display: "flex" }}>
            Scan any site free at {brand.domainSuggestion}
          </div>
        </div>
      </div>
    ),
    { width: 1200, height: 630 }
  );
}
