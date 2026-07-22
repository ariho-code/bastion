import { NextRequest, NextResponse } from "next/server";
import { runScan, ScanError } from "@/lib/scanner/engine";
import { emailConfigured, sendMonitorConfirm } from "@/lib/email";
import { kvConfigured, addMonitor, saveMonitor, removeMonitor } from "@/lib/monitor";
import { rateLimit } from "@/lib/ratelimit";
import { SITE_URL, brand } from "@/lib/brand";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  const ip = fwd ? fwd.split(",")[0].trim() : req.headers.get("x-real-ip") || "";
  return ip || "unknown";
}

const unsubUrl = (id: string) => `${SITE_URL}/api/monitor?unsubscribe=${id}`;

// Unsubscribe via emailed link.
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("unsubscribe");
  if (!id) return NextResponse.json({ error: "Missing unsubscribe id." }, { status: 400 });
  if (kvConfigured()) {
    try {
      await removeMonitor(id);
    } catch {
      /* ignore */
    }
  }
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Unsubscribed</title></head>
<body style="margin:0;font-family:system-ui,sans-serif;background:#0a0e14;color:#e7eef5;display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center;">
<div><div style="font-size:34px;color:#2dd4bf;">&#9672;</div><h1 style="font-weight:700;">Unsubscribed</h1>
<p style="color:#9db0c3;">You'll no longer receive monitoring alerts for this site.</p>
<a href="${SITE_URL}" style="color:#2dd4bf;">Back to ${brand.name}</a></div></body></html>`;
  return new NextResponse(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
}

// Subscribe a site to daily monitoring.
export async function POST(req: NextRequest) {
  if (!emailConfigured() || !kvConfigured()) {
    return NextResponse.json(
      { error: "Monitoring isn't enabled on the server yet." },
      { status: 503 }
    );
  }

  let body: { url?: string; email?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const email = (body?.email || "").trim().toLowerCase();
  const url = (body?.url || "").trim();
  if (!EMAIL_RE.test(email) || email.length > 200) {
    return NextResponse.json({ error: "Please enter a valid email address." }, { status: 400 });
  }
  if (!url) {
    return NextResponse.json({ error: "Nothing to monitor — run a scan first." }, { status: 400 });
  }

  const perIp = rateLimit(`monitor:ip:${clientIp(req)}`, 10, 60 * 60 * 1000);
  if (!perIp.ok) {
    return NextResponse.json({ error: "Too many requests. Try again later." }, { status: 429 });
  }

  try {
    const result = await runScan(url);
    const mon = await addMonitor(result.host, result.host, email);
    mon.lastGrade = result.grade;
    mon.lastScore = result.score;
    mon.lastCheckedAt = Date.now();
    await saveMonitor(mon);
    await sendMonitorConfirm(email, result.host, unsubUrl(mon.id));
    return NextResponse.json({ ok: true, host: result.host, grade: result.grade });
  } catch (e) {
    if (e instanceof ScanError) {
      return NextResponse.json({ error: e.message }, { status: e.status });
    }
    return NextResponse.json({ error: "Couldn't set up monitoring. Please try again." }, { status: 500 });
  }
}
