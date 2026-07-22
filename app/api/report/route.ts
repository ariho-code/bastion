import { NextRequest, NextResponse } from "next/server";
import { runScan, ScanError } from "@/lib/scanner/engine";
import { sendReportEmail, emailConfigured } from "@/lib/email";
import { rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  const ip = fwd ? fwd.split(",")[0].trim() : req.headers.get("x-real-ip") || "";
  return ip || "unknown";
}

export async function POST(req: NextRequest) {
  if (!emailConfigured()) {
    return NextResponse.json(
      { error: "Email delivery isn't configured on the server yet." },
      { status: 503 }
    );
  }

  let body: { email?: string; url?: string };
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
    return NextResponse.json({ error: "Nothing to scan — run a scan first." }, { status: 400 });
  }

  // Anti-abuse: protect the sending mailbox.
  const ip = clientIp(req);
  const perIp = rateLimit(`report:ip:${ip}`, 5, 60 * 60 * 1000); // 5 / hour / IP
  if (!perIp.ok) {
    return NextResponse.json(
      { error: `Too many report emails from here. Try again in ~${Math.ceil(perIp.retryAfter / 60)} min.` },
      { status: 429 }
    );
  }
  const perEmail = rateLimit(`report:email:${email}`, 3, 60 * 60 * 1000); // 3 / hour / recipient
  if (!perEmail.ok) {
    return NextResponse.json(
      { error: "That inbox has received several reports recently. Please try again later." },
      { status: 429 }
    );
  }

  try {
    const result = await runScan(url); // fresh, authentic scan — never client-supplied content
    await sendReportEmail(email, result);
    return NextResponse.json({ ok: true, grade: result.grade, score: result.score });
  } catch (e) {
    if (e instanceof ScanError) {
      return NextResponse.json({ error: e.message }, { status: e.status });
    }
    return NextResponse.json(
      { error: "Couldn't send the report right now. Please try again." },
      { status: 500 }
    );
  }
}
