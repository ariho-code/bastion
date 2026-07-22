"use client";

import { useEffect, useState } from "react";
import type { CategoryScore } from "@/lib/scanner/types";
import Icon, { type IconName } from "./Icon";

const CAT_ICON: Record<string, IconName> = {
  transport: "lock",
  headers: "shield",
  dns: "mail",
  cookies: "cookie",
  disclosure: "eye",
};

function barColor(score: number): string {
  return score >= 80 ? "#22c55e" : score >= 55 ? "#eab308" : "#ef4444";
}

/** Animated SVG-free horizontal bar chart of category scores. */
export default function CategoryChart({ categories }: { categories: CategoryScore[] }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(id);
  }, []);

  return (
    <div className="chart">
      <div className="chart-head">
        <Icon name="bar-chart" size={17} />
        <span>Score breakdown</span>
      </div>
      <div className="chart-rows">
        {categories.map((c) => {
          const color = barColor(c.score);
          return (
            <div className="chart-row" key={c.category}>
              <div className="chart-label">
                <Icon name={CAT_ICON[c.category] || "shield"} size={15} />
                <span>{c.label}</span>
              </div>
              <div className="chart-track">
                <div
                  className="chart-fill"
                  style={{ width: mounted ? `${c.score}%` : "0%", background: color }}
                />
              </div>
              <div className="chart-val" style={{ color }}>
                {c.score}
                <span className="chart-pct">%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
