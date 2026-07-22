import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

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
