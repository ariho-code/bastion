import { ImageResponse } from "next/og";
import { shieldSvg } from "@/lib/logoOg";

export const runtime = "edge";
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div style={{ width: 180, height: 180, display: "flex", background: "#0a0e14" }}>
        {shieldSvg(180)}
      </div>
    ),
    size
  );
}
