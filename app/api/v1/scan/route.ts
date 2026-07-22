import { NextRequest, NextResponse } from "next/server";
import { runScan, ScanError } from "@/lib/scanner/engine";
import {
  identify,
  requireKey,
  checkApiRate,
  CORS_HEADERS,
  rateHeaders,
} from "@/lib/apiauth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

function json(body: unknown, status: number, extra: Record<string, string> = {}) {
  return NextResponse.json(body, {
    status,
    headers: { ...CORS_HEADERS, "Cache-Control": "no-store", ...extra },
  });
}

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

async function handle(req: NextRequest, target: string) {
  const id = identify(req);

  if (!id.keyed && requireKey()) {
    return json(
      { ok: false, error: "An API key is required. Pass it as 'Authorization: Bearer <key>'." },
      401
    );
  }

  const rate = checkApiRate(req, id);
  const rh = rateHeaders(id, rate);
  if (!rate.ok) {
    return json(
      { ok: false, error: "Rate limit exceeded.", retryAfterSeconds: rate.retryAfter },
      429,
      { ...rh, "Retry-After": String(rate.retryAfter) }
    );
  }

  if (!target) {
    return json({ ok: false, error: "Missing required parameter 'url'." }, 400, rh);
  }

  try {
    const data = await runScan(target);
    return json({ ok: true, tier: id.tier, data }, 200, rh);
  } catch (e) {
    if (e instanceof ScanError) {
      return json({ ok: false, error: e.message }, e.status, rh);
    }
    return json({ ok: false, error: "Scan failed. Please try again." }, 500, rh);
  }
}

export async function GET(req: NextRequest) {
  const url = req.nextUrl.searchParams.get("url") || "";
  return handle(req, url.trim());
}

export async function POST(req: NextRequest) {
  let url = "";
  try {
    const body = await req.json();
    url = (body?.url || "").toString().trim();
  } catch {
    return json({ ok: false, error: "Invalid JSON body." }, 400);
  }
  return handle(req, url);
}
