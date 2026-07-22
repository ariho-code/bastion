import { ImageResponse } from "next/og";
import { shieldSvg } from "@/lib/logoOg";

export const runtime = "edge";

/** Square shield-mark PNG, used for apple-touch-icon and PWA manifest icons. ?size=192|512 etc. */
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const size = Math.min(1024, Math.max(16, Number(searchParams.get("size")) || 512));

  return new ImageResponse(
    (
      <div
        style={{
          width: size,
          height: size,
          display: "flex",
          background: "#0a0e14",
          borderRadius: size * 0.22,
        }}
      >
        {shieldSvg(size)}
      </div>
    ),
    { width: size, height: size }
  );
}
