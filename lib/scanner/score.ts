import type { Finding, CategoryScore, Category } from "./types";
import { CATEGORY_LABELS } from "./types";

export function gradeFromScore(pct: number): string {
  if (pct >= 90) return "A";
  if (pct >= 80) return "B";
  if (pct >= 70) return "C";
  if (pct >= 55) return "D";
  return "F";
}

const CATEGORY_ORDER: Category[] = ["transport", "headers", "dns", "cookies", "disclosure"];

export function scoreByCategory(findings: Finding[]): {
  categories: CategoryScore[];
  overall: number;
} {
  const categories: CategoryScore[] = [];
  let totalEarned = 0;
  let totalMax = 0;

  for (const cat of CATEGORY_ORDER) {
    const items = findings.filter((f) => f.category === cat && f.maxPoints > 0);
    if (items.length === 0) continue;
    const earned = items.reduce((a, f) => a + f.points, 0);
    const max = items.reduce((a, f) => a + f.maxPoints, 0);
    const all = findings.filter((f) => f.category === cat);
    categories.push({
      category: cat,
      label: CATEGORY_LABELS[cat],
      score: max > 0 ? Math.round((earned / max) * 100) : 0,
      earned,
      max,
      pass: all.filter((f) => f.status === "pass").length,
      warn: all.filter((f) => f.status === "warn").length,
      fail: all.filter((f) => f.status === "fail").length,
    });
    totalEarned += earned;
    totalMax += max;
  }

  const overall = totalMax > 0 ? Math.round((totalEarned / totalMax) * 100) : 0;
  return { categories, overall };
}

const STATUS_ORDER: Record<Finding["status"], number> = { fail: 0, warn: 1, pass: 2, info: 3 };
const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      b.maxPoints - a.maxPoints
  );
}
