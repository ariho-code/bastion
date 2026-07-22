import { NextRequest, NextResponse } from "next/server";
import { rateLimit } from "@/lib/ratelimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 120;

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

// The engine is authoritative for the Active tier: it confirms domain ownership
// via a DNS TXT token itself, so we can safely forward "active" without trusting
// any client flag. Unverified active scans simply skip the ownership-gated
// modules (surfaced in the UI), rather than being silently downgraded.
const PROFILES = new Set(["standard", "deep", "active"]);

export async function POST(req: NextRequest) {
  let body: {
    target?: string;
    profile?: string;
    scope?: {
      includePaths?: string[];
      excludePaths?: string[];
      excludeHosts?: string[];
      disableModules?: string[];
      enableModules?: string[];
      maxRequests?: number;
      requestDelayMs?: number;
      safeMode?: boolean;
    };
  };
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

  // Sanitize enterprise scope: only string arrays and small numbers.
  let scope: Record<string, unknown> | undefined;
  if (body.scope && typeof body.scope === "object") {
    const s = body.scope;
    scope = {};
    const strArr = (v: unknown, max = 50) =>
      Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, max) : undefined;
    if (s.includePaths) scope.includePaths = strArr(s.includePaths);
    if (s.excludePaths) scope.excludePaths = strArr(s.excludePaths);
    if (s.excludeHosts) scope.excludeHosts = strArr(s.excludeHosts);
    if (s.disableModules) scope.disableModules = strArr(s.disableModules, 40);
    if (s.enableModules) scope.enableModules = strArr(s.enableModules, 40);
    if (typeof s.maxRequests === "number" && s.maxRequests > 0)
      scope.maxRequests = Math.min(2000, Math.floor(s.maxRequests));
    if (typeof s.requestDelayMs === "number" && s.requestDelayMs >= 0)
      scope.requestDelayMs = Math.min(5000, Math.floor(s.requestDelayMs));
    if (typeof s.safeMode === "boolean") scope.safeMode = s.safeMode;
  }

  const rl = rateLimit(`deep:${clientIP(req)}`, DEEP_LIMIT, DEEP_WINDOW_MS);
  if (!rl.ok) {
    return NextResponse.json(
      { error: "You're scanning too fast. Please wait a moment and try again." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfter) } }
    );
  }

  // Active DAST can run longer (many scoped probes).
  const timeoutMs = profile === "active" ? 90_000 : 55_000;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${BRAIN_URL}/v1/assess`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, profile, verified: false, scope }),
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
