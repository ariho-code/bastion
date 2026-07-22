import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const BRAIN_URL = (process.env.BASTION_BRAIN_URL || "http://localhost:8090").replace(/\/$/, "");

// Issues the DNS TXT record a user publishes to unlock Active-tier scans for a
// domain they own. Proxies to the brain (which asks the engine).
export async function GET(req: NextRequest) {
  const target = (req.nextUrl.searchParams.get("target") ?? "").trim();
  if (!target) {
    return NextResponse.json({ error: "Provide a target." }, { status: 400 });
  }
  try {
    const res = await fetch(`${BRAIN_URL}/v1/verify?target=${encodeURIComponent(target)}`, {
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return NextResponse.json({ error: data?.detail || data?.error || "Verification lookup failed." }, { status: res.status });
    }
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "The advanced backend is unavailable." }, { status: 503 });
  }
}
