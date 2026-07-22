import { NextRequest, NextResponse } from "next/server";
import { rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Deep scans are expensive (they drive the Go engine's active probes), so the
// proxy is rate-limited per client on top of the engine's own limiter.
const DEEP_LIMIT = 12; // requests
const DEEP_WINDOW_MS = 5 * 60_000; // per 5 minutes

function clientIP(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") || "unknown";
}

// Server-side URL of the Python analysis brain (which itself drives the Go
// engine). Set BASTION_BRAIN_URL in the environment after deploying the
// services to Render. Falls back to localhost for development.
const BRAIN_URL = (process.env.BASTION_BRAIN_URL || "http://localhost:8090").replace(/\/$/, "");

const PROFILES = new Set(["standard", "deep"]);

export async function POST(req: NextRequest) {
  let body: { target?: string; profile?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const target = (body?.target ?? "").trim();
  if (!target) {
    return NextResponse.json({ error: "Please provide a URL or hostname to scan." }, { status: 400 });
  }
  const profile = PROFILES.has(body?.profile ?? "") ? body!.profile : "standard";

  const rl = rateLimit(`deep:${clientIP(req)}`, DEEP_LIMIT, DEEP_WINDOW_MS);
  if (!rl.ok) {
    return NextResponse.json(
      { error: "You're scanning too fast. Please wait a moment and try again." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfter) } }
    );
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 55_000);
  try {
    const res = await fetch(`${BRAIN_URL}/v1/assess`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, profile, verified: false }),
      signal: controller.signal,
      cache: "no-store",
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg =
        (data && (data.detail || data.error)) ||
        "The advanced scanning backend returned an error.";
      return NextResponse.json({ error: String(msg) }, { status: res.status });
    }
    return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    const aborted = e instanceof Error && e.name === "AbortError";
    return NextResponse.json(
      {
        error: aborted
          ? "The deep scan took too long and timed out. Try the Standard profile."
          : "The advanced backend is unavailable. Set BASTION_BRAIN_URL to your deployed engine.",
      },
      { status: aborted ? 504 : 503 }
    );
  } finally {
    clearTimeout(timeout);
  }
}
