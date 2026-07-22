import type { NextRequest } from "next/server";
import { rateLimit, type RateResult } from "./ratelimit";

export type ApiTier = "anonymous" | "pro" | "agency";

export interface ApiIdentity {
  keyed: boolean;
  keyId: string;
  tier: ApiTier;
  limit: number;
  windowMs: number;
}

const DAY = 24 * 60 * 60 * 1000;

const TIER_LIMITS: Record<ApiTier, number> = {
  anonymous: 30, // per day per IP — enough to try it out
  pro: 5000,
  agency: 100000,
};

function mask(key: string): string {
  if (key.length <= 6) return "key_••••";
  return key.slice(0, 4) + "…" + key.slice(-2);
}

/** Parse API_KEYS env: "key1:pro,key2:agency" (tier defaults to pro). */
function parseKeys(): Map<string, ApiTier> {
  const map = new Map<string, ApiTier>();
  for (const part of (process.env.API_KEYS || "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const [key, tier] = part.split(":");
    if (key) map.set(key, tier === "agency" ? "agency" : "pro");
  }
  return map;
}

export function requireKey(): boolean {
  return process.env.API_REQUIRE_KEY === "true";
}

export function extractKey(req: NextRequest): string {
  const auth = req.headers.get("authorization") || "";
  if (/^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, "").trim();
  return (req.headers.get("x-api-key") || "").trim();
}

export function identify(req: NextRequest): ApiIdentity {
  const key = extractKey(req);
  const keys = parseKeys();
  if (key && keys.has(key)) {
    const tier = keys.get(key)!;
    return { keyed: true, keyId: mask(key), tier, limit: TIER_LIMITS[tier], windowMs: DAY };
  }
  return { keyed: false, keyId: "anonymous", tier: "anonymous", limit: TIER_LIMITS.anonymous, windowMs: DAY };
}

export function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  const ip = fwd ? fwd.split(",")[0].trim() : req.headers.get("x-real-ip") || "";
  return ip || "unknown";
}

export function checkApiRate(req: NextRequest, id: ApiIdentity): RateResult {
  const bucket = id.keyed ? `api:key:${id.keyId}` : `api:ip:${clientIp(req)}`;
  return rateLimit(bucket, id.limit, id.windowMs);
}

export const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key",
  "Access-Control-Max-Age": "86400",
};

export function rateHeaders(id: ApiIdentity, r: RateResult): Record<string, string> {
  return {
    "X-RateLimit-Limit": String(id.limit),
    "X-RateLimit-Remaining": String(Math.max(0, r.remaining)),
    "X-RateLimit-Tier": id.tier,
  };
}
