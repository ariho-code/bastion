import type { ScanResult, Finding } from "./scanner/types";
import { brand, SITE_URL } from "./brand";
import { EMAIL_LOGO_HEIGHT, EMAIL_LOGO_WIDTH } from "./logoMark";

const GRADE_HEX: Record<string, string> = {
  A: "#16a34a",
  B: "#65a30d",
  C: "#ca8a04",
  D: "#ea580c",
  F: "#dc2626",
};

const STATUS_HEX: Record<Finding["status"], string> = {
  pass: "#16a34a",
  warn: "#ca8a04",
  fail: "#dc2626",
  info: "#64748b",
};

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function gradeVerdict(grade: string): string {
  return (
    {
      A: "Excellent — your security posture is strong and well ahead of most of the web.",
      B: "Good — solid foundations with a few quick wins left to reach an A.",
      C: "Fair — some important protections are missing. The fixes below will move the needle fast.",
      D: "At risk — several key defenses are absent. We recommend prioritising the failed checks.",
      F: "Critical — core protections are missing and visitors may be exposed. Act on these today.",
    }[grade] || "Here is your latest website security report."
  );
}

function bar(scorePct: number, color: string): string {
  const w = Math.max(3, Math.min(100, Math.round(scorePct)));
  return `
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;">
    <tr>
      <td height="8" style="background:#e9edf2;border-radius:6px;padding:0;">
        <table role="presentation" width="${w}%" cellpadding="0" cellspacing="0">
          <tr><td height="8" style="background:${color};border-radius:6px;font-size:0;line-height:0;">&nbsp;</td></tr>
        </table>
      </td>
    </tr>
  </table>`;
}

/** Premium, email-client-safe HTML report. */
export function renderReportEmailHtml(result: ScanResult): string {
  const grade = result.grade;
  const gc = GRADE_HEX[grade] || "#64748b";
  const scanUrl = `${SITE_URL}/?url=${encodeURIComponent(result.host)}&grade=${encodeURIComponent(
    grade
  )}&score=${result.score}`;

  const categoryRows = result.categories
    .map((c) => {
      const col = c.score >= 80 ? "#16a34a" : c.score >= 55 ? "#ca8a04" : "#dc2626";
      return `
      <tr>
        <td style="padding:10px 0;font:600 14px/1.4 Helvetica,Arial,sans-serif;color:#0f172a;width:170px;">${esc(
          c.label
        )}</td>
        <td style="padding:10px 0 10px 12px;">${bar(c.score, col)}</td>
        <td style="padding:10px 0 10px 12px;font:700 13px/1.4 Helvetica,Arial,sans-serif;color:${col};text-align:right;width:44px;">${c.score}%</td>
      </tr>`;
    })
    .join("");

  const priority = result.findings
    .filter((f) => f.status === "fail" || f.status === "warn")
    .slice(0, 6);

  const findingCards =
    priority
      .map((f) => {
        const sc = STATUS_HEX[f.status];
        const label = f.status === "fail" ? "FAIL" : "WARN";
        const fix = f.fix
          ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;">
              <tr><td style="background:#0b1220;border-radius:8px;padding:12px 14px;font:12px/1.6 'Courier New',monospace;color:#c7d2e0;white-space:pre-wrap;">${esc(
                f.fix
              )}</td></tr>
            </table>`
          : "";
        return `
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:10px 0;border:1px solid #e6eaef;border-left:4px solid ${sc};border-radius:10px;">
          <tr><td style="padding:16px 18px;">
            <table role="presentation" cellpadding="0" cellspacing="0"><tr>
              <td style="background:${sc};color:#fff;font:700 10px/1 Helvetica,Arial,sans-serif;letter-spacing:.06em;padding:5px 8px;border-radius:5px;">${label}</td>
              <td style="padding-left:10px;font:700 15px/1.3 Helvetica,Arial,sans-serif;color:#0f172a;">${esc(
                f.title
              )}</td>
            </tr></table>
            <p style="margin:10px 0 0;font:14px/1.6 Helvetica,Arial,sans-serif;color:#475569;">${esc(
              f.detail
            )}</p>
            ${fix}
          </td></tr>
        </table>`;
      })
      .join("") ||
    `<p style="font:15px/1.6 Helvetica,Arial,sans-serif;color:#16a34a;text-align:center;padding:16px;">No failing or warning checks — outstanding work. 🎉</p>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>${esc(brand.name)} Security Report</title></head>
<body style="margin:0;padding:0;background:#eef1f5;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">Your ${esc(
    brand.name
  )} security report for ${esc(result.host)} — grade ${esc(grade)} (${result.score}/100).</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;padding:28px 12px;">
<tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(15,23,42,.08);">

    <!-- Header -->
    <tr><td style="background:#0a0e14;padding:22px 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
        <td>
          <img src="${SITE_URL}/brand/logo-email" width="${EMAIL_LOGO_WIDTH}" height="${EMAIL_LOGO_HEIGHT}" alt="${esc(
    brand.name
  )}" style="display:block;border:0;outline:none;" />
        </td>
        <td style="text-align:right;font:500 13px/1.4 Helvetica,Arial,sans-serif;color:#8b9bb0;">Website Security Report</td>
      </tr></table>
    </td></tr>

    <!-- Grade hero -->
    <tr><td style="padding:32px 32px 8px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
        <td width="108" valign="top">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td width="92" height="92" align="center" valign="middle" style="background:${gc};border-radius:18px;font:800 52px/1 Helvetica,Arial,sans-serif;color:#ffffff;">${esc(
    grade
  )}</td>
          </tr></table>
        </td>
        <td valign="top" style="padding-left:8px;">
          <div style="font:700 20px/1.3 Helvetica,Arial,sans-serif;color:#0f172a;word-break:break-all;">${esc(
            result.host
          )}</div>
          <div style="margin-top:4px;font:600 14px/1.5 Helvetica,Arial,sans-serif;color:${gc};">Security score ${result.score}/100</div>
          <div style="margin-top:8px;font:14px/1.5 Helvetica,Arial,sans-serif;color:#64748b;">
            <span style="color:#16a34a;font-weight:700;">${result.passed}</span> passed &nbsp;·&nbsp;
            <span style="color:#ca8a04;font-weight:700;">${result.warnings}</span> warnings &nbsp;·&nbsp;
            <span style="color:#dc2626;font-weight:700;">${result.failed}</span> failed
          </div>
        </td>
      </tr></table>
      <p style="margin:20px 0 0;font:15px/1.6 Helvetica,Arial,sans-serif;color:#334155;">${gradeVerdict(
        grade
      )}</p>
    </td></tr>

    <!-- Category breakdown -->
    <tr><td style="padding:24px 32px 4px;">
      <div style="font:700 13px/1 Helvetica,Arial,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;padding-bottom:6px;">Category breakdown</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">${categoryRows}</table>
    </td></tr>

    <!-- CTA -->
    <tr><td style="padding:20px 32px 4px;">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        <td style="background:#2563eb;border-radius:10px;">
          <a href="${scanUrl}" style="display:inline-block;padding:13px 26px;font:700 15px/1 Helvetica,Arial,sans-serif;color:#ffffff;text-decoration:none;">View the live report &rarr;</a>
        </td>
      </tr></table>
    </td></tr>

    <!-- Priority findings -->
    <tr><td style="padding:24px 32px 8px;">
      <div style="font:700 13px/1 Helvetica,Arial,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8;padding-bottom:6px;">Priority fixes</div>
      ${findingCards}
    </td></tr>

    <!-- Footer -->
    <tr><td style="padding:26px 32px 30px;border-top:1px solid #eef1f5;">
      <p style="margin:0;font:12px/1.7 Helvetica,Arial,sans-serif;color:#94a3b8;">
        A full breakdown of all ${result.findings.length} checks is attached as a PDF.
        ${esc(brand.name)} performs a non-invasive scan of public HTTP data only.
      </p>
      <p style="margin:10px 0 0;font:12px/1.7 Helvetica,Arial,sans-serif;color:#b6c0cc;">
        You received this because it was requested from ${esc(
          brand.name
        )}. &copy; ${new Date().getFullYear()} ${esc(brand.name)}.
      </p>
    </td></tr>

  </table>
</td></tr></table>
</body></html>`;
}

/** Plain-text fallback for deliverability. */
export function renderReportEmailText(result: ScanResult): string {
  const lines = [
    `${brand.name} — Website Security Report`,
    ``,
    `Site: ${result.host}`,
    `Grade: ${result.grade} (${result.score}/100)`,
    `${result.passed} passed · ${result.warnings} warnings · ${result.failed} failed`,
    ``,
    gradeVerdict(result.grade),
    ``,
    `Category breakdown:`,
    ...result.categories.map((c) => `  - ${c.label}: ${c.score}%`),
    ``,
    `Priority fixes:`,
    ...result.findings
      .filter((f) => f.status === "fail" || f.status === "warn")
      .slice(0, 6)
      .map((f) => `  [${f.status.toUpperCase()}] ${f.title}\n      ${f.detail}`),
    ``,
    `Live report: ${SITE_URL}/?url=${encodeURIComponent(result.host)}`,
    `A full PDF report of all ${result.findings.length} checks is attached.`,
    ``,
    `${brand.name} — non-invasive scanning of public HTTP data.`,
  ];
  return lines.join("\n");
}
