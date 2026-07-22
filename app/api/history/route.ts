import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const BRAIN_URL = (process.env.BASTION_BRAIN_URL || "http://localhost:8090").replace(/\/$/, "");

export async function GET(req: NextRequest) {
  const tenant = req.nextUrl.searchParams.get("tenant") || "default";
  const limit = req.nextUrl.searchParams.get("limit") || "40";
  try {
    const res = await fetch(
      `${BRAIN_URL}/v1/history?tenant=${encodeURIComponent(tenant)}&limit=${encodeURIComponent(limit)}`,
      { cache: "no-store" }
    );
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return NextResponse.json(
        { error: data.detail || data.error || "History unavailable." },
        { status: res.status }
      );
    }
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Brain unavailable." }, { status: 503 });
  }
}
