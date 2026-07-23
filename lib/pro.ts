// Shared client-side entitlement + quota layer used by every scanner surface
// (home scan, advanced scan, and anything added later). Keeping this in one
// module means the whole product reads a single source of truth for "is this
// user Pro?" and daily usage — swap the localStorage flag for a real auth /
// billing check later and every surface upgrades at once.

export const FREE_SCAN_LIMIT = 20; // free standard scans per day (home)
export const FREE_ADVANCED_LIMIT = 5; // free advanced scans per day

const PRO_KEY = "bastion:pro";

// Product decision: the whole platform is currently FREE and fully open — every
// advanced and enterprise capability is unlocked for everyone. Billing/tiers
// will be wired up later. Because every surface reads isPro(), flipping this one
// switch back to `false` re-enables the Pro paywall across the entire product.
export const PRO_UNLOCKED_FOR_ALL = true;

/** True when the visitor has unlocked Pro. Currently true for everyone (free). */
export function isPro(): boolean {
  if (PRO_UNLOCKED_FOR_ALL) return true;
  try {
    return localStorage.getItem(PRO_KEY) === "1";
  } catch {
    return false;
  }
}

export function setPro(on: boolean): void {
  try {
    if (on) localStorage.setItem(PRO_KEY, "1");
    else localStorage.removeItem(PRO_KEY);
  } catch {
    /* noop */
  }
}

/** Honor ?pro=1 / ?pro=0 in the URL for manual unlock and testing. */
export function syncProFromURL(): void {
  try {
    const p = new URLSearchParams(window.location.search).get("pro");
    if (p === "1") setPro(true);
    else if (p === "0") setPro(false);
  } catch {
    /* noop */
  }
}

function todayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Scans used today for a named bucket (e.g. "scan", "advanced"). */
export function getQuota(bucket: string): number {
  try {
    const raw = JSON.parse(localStorage.getItem(`bastion:quota:${bucket}`) || "{}");
    return raw.day === todayKey() ? raw.count || 0 : 0;
  } catch {
    return 0;
  }
}

export function bumpQuota(bucket: string): void {
  try {
    const count = getQuota(bucket) + 1;
    localStorage.setItem(`bastion:quota:${bucket}`, JSON.stringify({ day: todayKey(), count }));
  } catch {
    /* noop */
  }
}

/** Remaining free scans in a bucket (0 when Pro is unlimited). */
export function remainingFree(bucket: string, limit: number): number {
  if (isPro()) return Infinity;
  return Math.max(0, limit - getQuota(bucket));
}
