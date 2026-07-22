import nodemailer from "nodemailer";
import type { Transporter } from "nodemailer";
import type { ScanResult } from "./scanner/types";
import { brand, SITE_URL } from "./brand";
import { renderReportEmailHtml, renderReportEmailText } from "./emailTemplate";
import { renderReportPdfBuffer } from "./pdf";
import { EMAIL_LOGO_HEIGHT, EMAIL_LOGO_WIDTH } from "./logoMark";

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

/** Confirm a new monitoring subscription. */
export async function sendMonitorConfirm(
  to: string,
  host: string,
  unsubscribeUrl: string
): Promise<void> {
  const t = getTransport();
  const cfg = getConfig();
  if (!t || !cfg) throw new Error("Email is not configured.");
  await t.sendMail({
    from: `"${brand.name} Monitoring" <${cfg.user}>`,
    to,
    replyTo: brand.contactEmail,
    subject: `Monitoring enabled for ${host}`,
    text: `${brand.name} is now monitoring ${host} daily and will email you the moment its security grade drops.\n\nUnsubscribe: ${unsubscribeUrl}`,
    html: `<div style="font-family:Helvetica,Arial,sans-serif;max-width:520px;margin:auto;padding:28px;color:#0f172a;">
      <img src="${SITE_URL}/brand/logo-email" width="${EMAIL_LOGO_WIDTH}" height="${EMAIL_LOGO_HEIGHT}" alt="${brand.name}" style="display:block;border:0;outline:none;background:#0a0e14;padding:10px 14px;border-radius:8px;" />
      <h2 style="margin:18px 0 8px;font-size:20px;">Monitoring is on &#9989;</h2>
      <p style="color:#475569;font-size:15px;line-height:1.6;">We'll re-scan <strong>${host}</strong> every day and email you the moment its security grade drops — so you never get caught out by a silent regression.</p>
      <p style="font-size:12px;color:#94a3b8;margin-top:20px;">Not you, or changed your mind? <a href="${unsubscribeUrl}" style="color:#2563eb;">Unsubscribe</a>.</p>
    </div>`,
  });
}

/** Alert a subscriber that a monitored site's grade dropped. */
export async function sendMonitorAlert(
  to: string,
  result: ScanResult,
  prevGrade: string,
  unsubscribeUrl: string
): Promise<void> {
  const t = getTransport();
  const cfg = getConfig();
  if (!t || !cfg) throw new Error("Email is not configured.");

  const attachments: { filename: string; content: Buffer; contentType: string }[] = [];
  try {
    const pdf = await renderReportPdfBuffer(result);
    attachments.push({
      filename: `${brand.name}-report-${result.host}.pdf`,
      content: pdf,
      contentType: "application/pdf",
    });
  } catch {
    /* still send the HTML alert */
  }

  const html = renderReportEmailHtml(result).replace(
    "</body>",
    `<div style="text-align:center;padding:14px;font:12px Helvetica,Arial,sans-serif;color:#94a3b8;"><a href="${unsubscribeUrl}" style="color:#94a3b8;">Unsubscribe from monitoring</a></div></body>`
  );

  await t.sendMail({
    from: `"${brand.name} Monitoring" <${cfg.user}>`,
    to,
    replyTo: brand.contactEmail,
    subject: `⚠️ ${result.host} dropped to ${result.grade} (was ${prevGrade})`,
    text: `Heads up — ${result.host} dropped from ${prevGrade} to ${result.grade} (${result.score}/100). The full report is attached.\n\nUnsubscribe: ${unsubscribeUrl}`,
    html,
    attachments,
  });
}
