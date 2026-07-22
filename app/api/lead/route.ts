import { NextRequest, NextResponse } from "next/server";
import { sendWaitlistEmail, emailConfigured } from "@/lib/email";
import { rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  const ip = fwd ? fwd.split(",")[0].trim() : req.headers.get("x-real-ip") || "";
  return ip || "unknown";
}

export async function POST(req: NextRequest) {
  if (!emailConfigured()) {
    return NextResponse.json({ error: "Waitlist isn't available yet." }, { status: 503 });
  }

  let body: { email?: string; plan?: string; note?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const email = (body?.email || "").trim().toLowerCase();
  const plan = (body?.plan || "Pro").toString().slice(0, 40);
  const note = (body?.note || "").toString().slice(0, 500);

  if (!EMAIL_RE.test(email) || email.length > 200) {
    return NextResponse.json({ error: "Please enter a valid email address." }, { status: 400 });
  }

  const perIp = rateLimit(`lead:ip:${clientIp(req)}`, 8, 60 * 60 * 1000);
  if (!perIp.ok) {
    return NextResponse.json({ error: "Too many signups from here. Try later." }, { status: 429 });
  }

  try {
    await sendWaitlistEmail(email, plan, note);
    return NextResponse.json({ ok: true });
  } catch {
    return NextResponse.json({ error: "Couldn't sign you up. Please try again." }, { status: 500 });
  }
}
