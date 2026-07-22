import { kv } from "@vercel/kv";

const INDEX = "bastion:monitors";
const key = (id: string) => `bastion:monitor:${id}`;

/** Vercel KV / Upstash is only active when its env vars are injected. */
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

/** Deterministic short id (djb2) so re-subscribing dedupes. */
export function monitorId(url: string, email: string): string {
  const s = `${url.toLowerCase()}|${email.toLowerCase()}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

export async function addMonitor(url: string, host: string, email: string): Promise<Monitor> {
  const id = monitorId(url, email);
  const existing = (await kv.get<Monitor>(key(id))) ?? null;
  const mon: Monitor =
    existing ?? {
      id,
      url,
      host,
      email,
      lastGrade: null,
      lastScore: null,
      createdAt: Date.now(),
      lastCheckedAt: null,
    };
  await kv.set(key(id), mon);
  await kv.sadd(INDEX, id);
  return mon;
}

export async function listMonitorIds(): Promise<string[]> {
  return ((await kv.smembers(INDEX)) as string[]) || [];
}

export async function getMonitor(id: string): Promise<Monitor | null> {
  return (await kv.get<Monitor>(key(id))) ?? null;
}

export async function saveMonitor(m: Monitor): Promise<void> {
  await kv.set(key(m.id), m);
}

export async function removeMonitor(id: string): Promise<void> {
  await kv.del(key(id));
  await kv.srem(INDEX, id);
}

const GRADE_RANK: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };

/** True when `next` is a worse letter grade than `prev`. */
export function gradeDropped(prev: string | null, next: string): boolean {
  if (!prev) return false;
  return (GRADE_RANK[next] ?? 0) < (GRADE_RANK[prev] ?? 0);
}
