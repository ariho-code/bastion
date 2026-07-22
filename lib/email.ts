import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import type { ScanResult } from "./scanner/types";
import { brand } from "./brand";
import { renderReportEmailHtml, renderReportEmailText } from "./emailTemplate";
import { renderReportPdfBuffer } from "./pdf";

interface MailConfig {
  user: string;
  pass: string;
}

function getConfig(): MailConfig | null {
  const user = process.env.GMAIL_USER || process.env.SMTP_USER;
  const pass = process.env.GMAIL_APP_PASSWORD || process.env.SMTP_PASS;
  if (!user || !pass) return null;
  return { user, pass };
}

export function emailConfigured(): boolean {
  return getConfig() !== null;
}

let transporter: Transporter | null = null;

function getTransport(): Transporter | null {
  const cfg = getConfig();
  if (!cfg) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: Number(process.env.SMTP_PORT || 465),
      secure: true,
      auth: { user: cfg.user, pass: cfg.pass },
    });
  }
  return transporter;
}

/**
 * Email a scan report (premium HTML + PDF attachment) to the requester.
 * The content is always a freshly-scanned, fixed-format security report, so the
 * endpoint can't be weaponised to send arbitrary content.
 */
export async function sendReportEmail(to: string, result: ScanResult): Promise<void> {
  const t = getTransport();
  const cfg = getConfig();
  if (!t || !cfg) throw new Error("Email is not configured.");

  const attachments: {
    filename: string;
    content: Buffer;
    contentType: string;
  }[] = [];

  try {
    const pdf = await renderReportPdfBuffer(result);
    attachments.push({
      filename: `${brand.name}-report-${result.host}.pdf`,
      content: pdf,
      contentType: "application/pdf",
    });
  } catch {
    // PDF generation failed — still deliver the rich HTML report.
  }

  await t.sendMail({
    from: `"${brand.name} Security" <${cfg.user}>`,
    to,
    replyTo: brand.contactEmail,
    subject: `${result.host} scored ${result.grade} — your ${brand.name} security report`,
    text: renderReportEmailText(result),
    html: renderReportEmailHtml(result),
    attachments,
  });

  // Fire-and-forget internal lead notice (helps build a sales pipeline).
  if (process.env.LEAD_NOTIFY !== "false") {
    t
      .sendMail({
        from: `"${brand.name}" <${cfg.user}>`,
        to: cfg.user,
        subject: `New lead: ${to} scanned ${result.host} (${result.grade})`,
        text: `${to} requested a report for ${result.host}.\nGrade ${result.grade} (${result.score}/100).`,
      })
      .catch(() => {
        /* non-critical */
      });
  }
}

/** Capture a paid-plan waitlist signup: notify the owner + confirm to the user. */
export async function sendWaitlistEmail(email: string, plan: string, note?: string): Promise<void> {
  const t = getTransport();
  const cfg = getConfig();
  if (!t || !cfg) throw new Error("Email is not configured.");

  await t.sendMail({
    from: `"${brand.name}" <${cfg.user}>`,
    to: cfg.user,
    replyTo: email,
    subject: `Waitlist: ${email} wants ${brand.name} ${plan}`,
    text: `${email} joined the ${plan} waitlist.${note ? `\nNote: ${note}` : ""}`,
  });

  t
    .sendMail({
      from: `"${brand.name}" <${cfg.user}>`,
      to: email,
      subject: `You're on the ${brand.name} ${plan} waitlist`,
      text: `Thanks for your interest in ${brand.name} ${plan}. We'll email you the moment it's ready.\n\nIn the meantime, keep scanning for free at ${brand.domainSuggestion}.`,
    })
    .catch(() => {
      /* confirmation is best-effort */
    });
}
