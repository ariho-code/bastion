import { ImageResponse } from "next/og";
import { brand } from "@/lib/brand";
import { shieldSvg } from "@/lib/logoOg";

export const runtime = "edge";
export const alt = `${brand.name} — Website Security Scanner`;
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OgImage() {
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
          padding: "72px",
          fontFamily: "sans-serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {shieldSvg(48)}
          <div style={{ display: "flex", fontSize: 40, fontWeight: 700 }}>
            <span style={{ color: "#e6edf3" }}>Bastion</span>
            <span style={{ color: "#3b82f6" }}>scan</span>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          <div style={{ fontSize: 68, color: "#ffffff", fontWeight: 800, lineHeight: 1.05 }}>
            Is your website
          </div>
          <div style={{ fontSize: 68, fontWeight: 800, lineHeight: 1.05, color: "#3b82f6" }}>
            actually secure?
          </div>
          <div style={{ fontSize: 30, color: "#93a1b3", marginTop: 8 }}>
            Grade any site A–F across TLS, headers, DNS &amp; cookies — with the exact fixes.
          </div>
        </div>

        <div style={{ display: "flex", gap: 16 }}>
          {["A", "B", "C", "D", "F"].map((g, i) => (
            <div
              key={g}
              style={{
                width: 64,
                height: 64,
                borderRadius: 14,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 34,
                fontWeight: 800,
                color: "#0a0e14",
                background: ["#22c55e", "#84cc16", "#eab308", "#f97316", "#ef4444"][i],
              }}
            >
              {g}
            </div>
          ))}
          <div style={{ flex: 1 }} />
          <div style={{ fontSize: 26, color: "#5f6f82", display: "flex", alignItems: "center" }}>
            {brand.domainSuggestion}
          </div>
        </div>
      </div>
    ),
    size
  );
}
