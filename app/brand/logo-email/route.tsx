import { ImageResponse } from "next/og";
import { shieldSvg } from "@/lib/logoOg";
import { EMAIL_LOGO_HEIGHT, EMAIL_LOGO_SCALE, EMAIL_LOGO_WIDTH } from "@/lib/logoMark";

export const runtime = "edge";

/** Hosted PNG lockup (shield + wordmark) for email clients, which can't render inline SVG. Transparent background. */
export async function GET() {
  const w = EMAIL_LOGO_WIDTH * EMAIL_LOGO_SCALE;
  const h = EMAIL_LOGO_HEIGHT * EMAIL_LOGO_SCALE;
  const markSize = 34 * EMAIL_LOGO_SCALE;

  return new ImageResponse(
    (
      <div
        style={{
          width: w,
          height: h,
          display: "flex",
          alignItems: "center",
          gap: 9 * EMAIL_LOGO_SCALE,
        }}
      >
        {shieldSvg(markSize)}
        <div
          style={{
            display: "flex",
            fontSize: 21 * EMAIL_LOGO_SCALE,
            fontWeight: 700,
            fontFamily: "sans-serif",
          }}
        >
          <span style={{ color: "#f5f8fc" }}>Bastion</span>
          <span style={{ color: "#3b82f6" }}>scan</span>
        </div>
      </div>
    ),
    { width: w, height: h }
  );
}
