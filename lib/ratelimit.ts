/**
 * Best-effort in-memory rate limiter. On serverless this is per-instance and
 * resets on cold start — enough to blunt casual abuse and protect the sending
 * mailbox. For hard guarantees at scale, back this with Upstash / Vercel KV.
 */
interface Bucket {
  count: number;
  reset: number;
}

const store = new Map<string, Bucket>();

export interface RateResult {
  ok: boolean;
  remaining: number;
  retryAfter: number; // seconds
}

export function rateLimit(key: string, limit: number, windowMs: number): RateResult {
  const now = Date.now();
  const b = store.get(key);

  if (!b || now > b.reset) {
    store.set(key, { count: 1, reset: now + windowMs });
    // Opportunistic prune so the map can't grow unbounded.
    if (store.size > 5000) {
      for (const [k, v] of store) if (now > v.reset) store.delete(k);
    }
    return { ok: true, remaining: limit - 1, retryAfter: 0 };
  }

  if (b.count >= limit) {
    return { ok: false, remaining: 0, retryAfter: Math.ceil((b.reset - now) / 1000) };
  }

  b.count += 1;
  return { ok: true, remaining: limit - b.count, retryAfter: 0 };
}
