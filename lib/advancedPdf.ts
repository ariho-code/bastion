import type { jsPDF as JsPDFType } from "jspdf";
import { brand } from "./brand";
import { GRADE_RGB, drawShieldMark } from "./pdf";

// Loose structural mirror of the brain's /v1/assess response. Typed permissively
// (strings, not literal unions) so the advanced scanner's stricter types are
// assignable without a shared import.
interface Finding {
  id: string;
  category: string;
  title: string;
  status: string;
  severity: string;
  detail: string;
  fix?: string;
  evidence?: string;
}
interface CVEMatch {
  product: string;
  version: string;
  fixed_in: string;
  severity: string;
  cves: string[];
  summary: string;
  source?: string;
}
interface CategoryRisk {
  label: string;
  risk: number;
}
interface RemediationItem {
  priority: string;
  severity: string;
  title: string;
  detail: string;
  fix?: string;
  effort: string;
}
interface Analysis {
  grade: string;
  score: number;
  risk_index: number;
  risk_level: string;
  headline: string;
  summary: string[];
  strengths: string[];
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  category_risk: CategoryRisk[];
  cve_matches: CVEMatch[];
  remediation: RemediationItem[];
}
interface Scan {
  host: string;
  profile: string;
  verified: boolean;
  findings: Finding[];
  passed: number;
  warnings: number;
  failed: number;
  durationMs: number;
}
export interface AdvancedReportData {
  scan: Scan;
  analysis: Analysis;
}

export interface WhiteLabel {
  company?: string;
}

const RISK_RGB: Record<string, [number, number, number]> = {
  Critical: [220, 38, 38],
  High: [234, 88, 12],
  Medium: [202, 138, 4],
  Low: [101, 163, 13],
  Minimal: [22, 163, 74],
};
const SEV_RGB: Record<string, [number, number, number]> = {
  critical: [220, 38, 38],
  high: [234, 88, 12],
  medium: [202, 138, 4],
  low: [101, 163, 13],
  info: [120, 135, 150],
};

const INK: [number, number, number] = [20, 26, 34];
const MUTE: [number, number, number] = [90, 100, 115];

/** Build the branded advanced-report PDF (executive risk report). */
export async function buildAdvancedReportDoc(
  data: AdvancedReportData,
  wl: WhiteLabel = {}
): Promise<JsPDFType> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const { scan, analysis } = data;
  const company = (wl.company || "").trim();

  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const margin = 48;
  const contentW = pageW - margin * 2;
  let y = margin;

  const ensure = (needed: number) => {
    if (y + needed > pageH - margin) {
      doc.addPage();
      y = margin;
    }
  };
  const sectionTitle = (label: string) => {
    ensure(40);
    y += 6;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(...INK);
    doc.text(label, margin, y);
    y += 8;
    doc.setDrawColor(226, 230, 235);
    doc.line(margin, y, pageW - margin, y);
    y += 16;
  };

  // --- Header band ----------------------------------------------------------
  doc.setFillColor(10, 14, 20);
  doc.rect(0, 0, pageW, 96, "F");
  drawShieldMark(doc, margin, 22, 40);
  const wordmarkX = margin + 40 * (48 / 56) + 12;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.setTextColor(245, 248, 252);
  doc.text("Bastion", wordmarkX, 46);
  const bastionWidth = doc.getTextWidth("Bastion");
  doc.setTextColor(59, 130, 246);
  doc.text("scan", wordmarkX + bastionWidth, 46);
  doc.setTextColor(200, 210, 220);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text("Advanced Security Report", wordmarkX, 66);
  doc.setTextColor(120, 135, 150);
  doc.setFontSize(9);
  doc.text(new Date().toLocaleString(), pageW - margin, 46, { align: "right" });
  doc.text(company ? `Prepared for ${company}` : brand.domainSuggestion, pageW - margin, 66, {
    align: "right",
  });

  // --- Cover / grade + risk -------------------------------------------------
  y = 130;
  const g = GRADE_RGB[analysis.grade] || [148, 163, 184];
  doc.setFillColor(g[0], g[1], g[2]);
  doc.roundedRect(margin, y, 84, 84, 10, 10, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(48);
  doc.text(analysis.grade || "—", margin + 42, y + 58, { align: "center" });

  doc.setTextColor(...INK);
  doc.setFontSize(18);
  doc.text(scan.host, margin + 104, y + 20);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(...MUTE);
  doc.text(
    `Security score ${analysis.score}/100  ·  ${scan.profile} scan${scan.verified ? " · ownership verified" : ""}`,
    margin + 104,
    y + 42
  );

  // Risk index chip
  const rr = RISK_RGB[analysis.risk_level] || [148, 163, 184];
  doc.setFillColor(rr[0], rr[1], rr[2]);
  doc.roundedRect(margin + 104, y + 54, 150, 22, 5, 5, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text(`Risk ${analysis.risk_index}/100 · ${analysis.risk_level}`, margin + 104 + 75, y + 69, {
    align: "center",
  });

  // Severity tally
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9.5);
  doc.setTextColor(...MUTE);
  doc.text(
    `${analysis.critical_count} critical · ${analysis.high_count} high · ${analysis.medium_count} medium · ${analysis.low_count} low`,
    margin + 104 + 165,
    y + 69
  );
  y += 84 + 24;

  // Headline
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11.5);
  doc.setTextColor(...INK);
  for (const line of doc.splitTextToSize(analysis.headline, contentW)) {
    ensure(16);
    doc.text(line, margin, y);
    y += 15;
  }
  y += 6;

  // --- Executive summary ----------------------------------------------------
  if (analysis.summary.length) {
    sectionTitle("Executive summary");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    for (const s of analysis.summary) {
      const lines = doc.splitTextToSize(s, contentW - 16);
      ensure(lines.length * 13 + 4);
      doc.setFillColor(59, 130, 246);
      doc.circle(margin + 3, y - 3, 1.8, "F");
      doc.setTextColor(60, 70, 85);
      doc.text(lines, margin + 14, y);
      y += lines.length * 13 + 4;
    }
    y += 6;
  }

  // --- Known vulnerabilities ------------------------------------------------
  if (analysis.cve_matches.length) {
    const live = analysis.cve_matches.some((m) => m.source === "osv");
    sectionTitle(`Known vulnerabilities${live ? " (live feed)" : ""}`);
    doc.setFontSize(10);
    for (const m of analysis.cve_matches) {
      const ids = m.cves.join(", ");
      const line1 = `${m.product} ${m.version} → upgrade to ${m.fixed_in}+`;
      const sumLines = doc.splitTextToSize(`${m.summary}  [${ids}]`, contentW - 70);
      ensure(sumLines.length * 12 + 22);
      const sc = SEV_RGB[m.severity] || SEV_RGB.info;
      doc.setFillColor(sc[0], sc[1], sc[2]);
      doc.roundedRect(margin, y - 8, 52, 14, 3, 3, "F");
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(7.5);
      doc.text(m.severity.toUpperCase(), margin + 26, y + 1.5, { align: "center" });
      doc.setTextColor(...INK);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10.5);
      doc.text(line1, margin + 62, y + 2);
      y += 16;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(...MUTE);
      doc.text(sumLines, margin + 62, y);
      y += sumLines.length * 12 + 8;
    }
    y += 2;
  }

  // --- Risk by category -----------------------------------------------------
  if (analysis.category_risk.length) {
    sectionTitle("Risk by category");
    for (const c of analysis.category_risk) {
      ensure(22);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(60, 70, 85);
      doc.text(c.label, margin, y + 9);
      const barX = margin + 150;
      const barW = contentW - 150 - 42;
      doc.setFillColor(230, 234, 239);
      doc.roundedRect(barX, y, barW, 10, 5, 5, "F");
      // Higher risk is worse → red at the top of the range.
      const cg = c.risk >= 60 ? [220, 38, 38] : c.risk >= 30 ? [202, 138, 4] : [22, 163, 74];
      doc.setFillColor(cg[0], cg[1], cg[2]);
      doc.roundedRect(barX, y, Math.max(6, (barW * c.risk) / 100), 10, 5, 5, "F");
      doc.setTextColor(60, 70, 85);
      doc.text(`${c.risk}`, pageW - margin, y + 9, { align: "right" });
      y += 22;
    }
    y += 6;
  }

  // --- Prioritized remediation ----------------------------------------------
  if (analysis.remediation.length) {
    sectionTitle("Prioritized remediation");
    doc.setFontSize(10);
    for (const r of analysis.remediation.slice(0, 24)) {
      const detailLines = doc.splitTextToSize(r.detail, contentW - 70);
      const fixLines = r.fix ? doc.splitTextToSize(`Fix: ${r.fix}`, contentW - 70) : [];
      ensure(detailLines.length * 12 + fixLines.length * 12 + 22);
      const sc = SEV_RGB[r.severity] || SEV_RGB.info;
      doc.setFillColor(sc[0], sc[1], sc[2]);
      doc.roundedRect(margin, y - 8, 34, 14, 3, 3, "F");
      doc.setTextColor(255, 255, 255);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(7.5);
      doc.text(r.priority, margin + 17, y + 1.5, { align: "center" });
      doc.setTextColor(...INK);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10.5);
      doc.text(`${r.title}  ·  ${r.effort}`, margin + 44, y + 2);
      y += 15;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(...MUTE);
      doc.text(detailLines, margin + 44, y);
      y += detailLines.length * 12;
      if (fixLines.length) {
        doc.setTextColor(29, 78, 216);
        doc.text(fixLines, margin + 44, y);
        y += fixLines.length * 12;
      }
      y += 8;
    }
  }

  // --- Footer on every page -------------------------------------------------
  const footer = company
    ? `Prepared by ${company} · Powered by ${brand.name} (${brand.domainSuggestion})`
    : `Generated by ${brand.name} — ${brand.domainSuggestion}. Advanced engine + risk brain.`;
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 172);
    doc.text(footer, margin, pageH - 24);
    doc.text(`${i} / ${pages}`, pageW - margin, pageH - 24, { align: "right" });
  }

  return doc;
}

/** Client-side: build and trigger a browser download. */
export async function downloadAdvancedReport(
  data: AdvancedReportData,
  wl: WhiteLabel = {}
): Promise<void> {
  const doc = await buildAdvancedReportDoc(data, wl);
  const who = (wl.company || brand.name).replace(/[^\w.-]+/g, "-");
  doc.save(`${who}-advanced-report-${data.scan.host}.pdf`);
}
