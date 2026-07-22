import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner/engine";
import {
  kvConfigured,
  listMonitorIds,
  getMonitor,
  saveMonitor,
  gradeDropped,
} from "@/lib/monitor";
import { sendMonitorAlert } from "@/lib/email";
import { SITE_URL } from "@/lib/brand";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const MONITORS_PER_RUN = 20;
const CONCURRENCY = 4;

export async function GET(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "CRON_SECRET is not set." }, { status: 503 });
  }
  const auth = req.headers.get("authorization") || "";
  const q = req.nextUrl.searchParams.get("secret") || "";
  if (auth !== `Bearer ${secret}` && q !== secret) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  if (!kvConfigured()) {
    return NextResponse.json({ ok: true, skipped: "kv-not-configured" });
  }

  const ids = (await listMonitorIds()).slice(0, MONITORS_PER_RUN);
  let checked = 0;
  let alerted = 0;
  let cursor = 0;

  async function worker() {
    while (cursor < ids.length) {
      const id = ids[cursor++];
      const mon = await getMonitor(id);
      if (!mon) continue;
      try {
        const result = await runScan(mon.url);
        checked++;
        const prev = mon.lastGrade;
        if (gradeDropped(prev, result.grade)) {
          await sendMonitorAlert(
            mon.email,
            result,
            prev as string,
            `${SITE_URL}/api/monitor?unsubscribe=${id}`
          );
          alerted++;
        }
        mon.lastGrade = result.grade;
        mon.lastScore = result.score;
        mon.lastCheckedAt = Date.now();
        await saveMonitor(mon);
      } catch {
        /* skip a failing target this run */
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(CONCURRENCY, ids.length) }, () => worker())
  );

  return NextResponse.json({ ok: true, total: ids.length, checked, alerted });
}
