import { kv } from "@vercel/kv";

const INDEX = "bastion:monitors";
const key = (id: string) => `bastion:monitor:${id}`;

/** Vercel KV / Upstash is active when its env vars are injected. When it isn't,
 *  we fall back to an in-memory store so monitoring is still fully testable
 *  (subscribe + confirmation email work); KV just adds durable persistence. */
export function kvConfigured(): boolean {
  return !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
}

export interface Monitor {
  id: string;
  url: string;
  host: string;
  email: string;
  lastGrade: string | null;
  lastScore: number | null;
  createdAt: number;
  lastCheckedAt: number | null;
}

// In-memory fallback (per server instance).
const memStore = new Map<string, Monitor>();
const memIndex = new Set<string>();

/** Deterministic short id (djb2) so re-subscribing dedupes. */
export function monitorId(url: string, email: string): string {
  const s = `${url.toLowerCase()}|${email.toLowerCase()}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

function newMonitor(id: string, url: string, host: string, email: string): Monitor {
  return {
    id,
    url,
    host,
    email,
    lastGrade: null,
    lastScore: null,
    createdAt: Date.now(),
    lastCheckedAt: null,
  };
}

export async function addMonitor(url: string, host: string, email: string): Promise<Monitor> {
  const id = monitorId(url, email);
  if (kvConfigured()) {
    const existing = (await kv.get<Monitor>(key(id))) ?? null;
    const mon = existing ?? newMonitor(id, url, host, email);
    await kv.set(key(id), mon);
    await kv.sadd(INDEX, id);
    return mon;
  }
  const mon = memStore.get(id) ?? newMonitor(id, url, host, email);
  memStore.set(id, mon);
  memIndex.add(id);
  return mon;
}

export async function listMonitorIds(): Promise<string[]> {
  if (kvConfigured()) return ((await kv.smembers(INDEX)) as string[]) || [];
  return Array.from(memIndex);
}

export async function getMonitor(id: string): Promise<Monitor | null> {
  if (kvConfigured()) return (await kv.get<Monitor>(key(id))) ?? null;
  return memStore.get(id) ?? null;
}

export async function saveMonitor(m: Monitor): Promise<void> {
  if (kvConfigured()) {
    await kv.set(key(m.id), m);
    return;
  }
  memStore.set(m.id, m);
  memIndex.add(m.id);
}

export async function removeMonitor(id: string): Promise<void> {
  if (kvConfigured()) {
    await kv.del(key(id));
    await kv.srem(INDEX, id);
    return;
  }
  memStore.delete(id);
  memIndex.delete(id);
}

const GRADE_RANK: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };

/** True when `next` is a worse letter grade than `prev`. */
export function gradeDropped(prev: string | null, next: string): boolean {
  if (!prev) return false;
  return (GRADE_RANK[next] ?? 0) < (GRADE_RANK[prev] ?? 0);
}
