import type { ScanResult, Finding } from "./scanner/types";
import { brand } from "./brand";

const GRADE_RGB: Record<string, [number, number, number]> = {
  A: [34, 197, 94],
  B: [132, 204, 22],
  C: [234, 179, 8],
  D: [249, 115, 22],
  F: [239, 68, 68],
};

const STATUS_LABEL: Record<Finding["status"], string> = {
  pass: "PASS",
  warn: "WARN",
  fail: "FAIL",
  info: "INFO",
};

/** Generate and download a branded PDF report for a scan. Client-side only. */
export async function downloadReport(result: ScanResult): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const doc = new jsPDF({ unit: "pt", format: "a4" });

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

  // Header band
  doc.setFillColor(11, 15, 22);
  doc.rect(0, 0, pageW, 96, "F");
  doc.setTextColor(45, 212, 191);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.text(brand.name, margin, 46);
  doc.setTextColor(200, 210, 220);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text("Website Security Report", margin, 66);
  doc.setTextColor(120, 135, 150);
  doc.setFontSize(9);
  doc.text(new Date(result.scannedAt).toLocaleString(), pageW - margin, 46, { align: "right" });
  doc.text(brand.domainSuggestion, pageW - margin, 66, { align: "right" });

  y = 130;

  // Grade block
  const g = GRADE_RGB[result.grade] || [148, 163, 184];
  doc.setFillColor(g[0], g[1], g[2]);
  doc.roundedRect(margin, y, 84, 84, 10, 10, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(48);
  doc.text(result.grade, margin + 42, y + 58, { align: "center" });

  doc.setTextColor(20, 26, 34);
  doc.setFontSize(18);
  doc.text(result.host, margin + 104, y + 24);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(90, 100, 115);
  doc.text(`Overall security score: ${result.score}/100`, margin + 104, y + 46);
  doc.text(
    `${result.passed} passed  ·  ${result.warnings} warnings  ·  ${result.failed} failed`,
    margin + 104,
    y + 64
  );
  y += 84 + 28;

  // Category scores
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(20, 26, 34);
  doc.text("Category breakdown", margin, y);
  y += 16;

  for (const c of result.categories) {
    ensure(26);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(60, 70, 85);
    doc.text(c.label, margin, y + 10);
    // bar
    const barX = margin + 150;
    const barW = contentW - 150 - 42;
    doc.setFillColor(230, 234, 239);
    doc.roundedRect(barX, y, barW, 10, 5, 5, "F");
    const cg = c.score >= 80 ? [34, 197, 94] : c.score >= 55 ? [234, 179, 8] : [239, 68, 68];
    doc.setFillColor(cg[0], cg[1], cg[2]);
    doc.roundedRect(barX, y, Math.max(6, (barW * c.score) / 100), 10, 5, 5, "F");
    doc.setTextColor(60, 70, 85);
    doc.text(`${c.score}%`, pageW - margin, y + 10, { align: "right" });
    y += 22;
  }

  y += 10;
  doc.setDrawColor(225, 229, 234);
  doc.line(margin, y, pageW - margin, y);
  y += 20;

  // Findings
  doc.setFont("helvetica", "bold");
  doc.setFontSize(13);
  doc.setTextColor(20, 26, 34);
  doc.text("Detailed findings", margin, y);
  y += 18;

  const statusColor: Record<Finding["status"], [number, number, number]> = {
    pass: [34, 197, 94],
    warn: [234, 179, 8],
    fail: [239, 68, 68],
    info: [120, 135, 150],
  };

  for (const f of result.findings) {
    const detailLines = doc.splitTextToSize(f.detail, contentW - 8);
    const fixLines = f.fix ? doc.splitTextToSize(f.fix, contentW - 24) : [];
    const blockH = 20 + detailLines.length * 12 + (fixLines.length ? fixLines.length * 11 + 14 : 0) + 12;
    ensure(blockH);

    const sc = statusColor[f.status];
    doc.setFillColor(sc[0], sc[1], sc[2]);
    doc.roundedRect(margin, y, 34, 13, 3, 3, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.text(STATUS_LABEL[f.status], margin + 17, y + 9, { align: "center" });

    doc.setTextColor(20, 26, 34);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(f.title, margin + 42, y + 10);
    y += 20;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(80, 90, 105);
    doc.text(detailLines, margin + 4, y);
    y += detailLines.length * 12;

    if (fixLines.length) {
      y += 4;
      const boxH = fixLines.length * 11 + 10;
      doc.setFillColor(245, 247, 249);
      doc.roundedRect(margin + 4, y, contentW - 8, boxH, 4, 4, "F");
      doc.setTextColor(70, 90, 110);
      doc.setFont("courier", "normal");
      doc.setFontSize(8.5);
      doc.text(fixLines, margin + 12, y + 12);
      doc.setFont("helvetica", "normal");
      y += boxH + 6;
    }
    y += 8;
  }

  // Footer on every page
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 172);
    doc.text(
      `Generated by ${brand.name} — ${brand.domainSuggestion}. Non-invasive scan of public HTTP data.`,
      margin,
      pageH - 24
    );
    doc.text(`${i} / ${pages}`, pageW - margin, pageH - 24, { align: "right" });
  }

  doc.save(`${brand.name}-report-${result.host}.pdf`);
}
