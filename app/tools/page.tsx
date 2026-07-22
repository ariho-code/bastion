import type { Metadata } from "next";
import Link from "next/link";
import { TOOLS } from "@/lib/tools";
import { brand } from "@/lib/brand";

export const metadata: Metadata = {
  title: "Free Website Security Tools",
  description: `A suite of free security checkers from ${brand.name} — security headers, HSTS, CSP, SSL/TLS, DMARC, SPF, DNSSEC and cookies. Instant A–F grades with copy-paste fixes.`,
  alternates: { canonical: "/tools" },
};

export default function ToolsIndex() {
  return (
    <main className="legal tools-index">
      <span className="eyebrow">Free tools</span>
      <h1>Free website security tools</h1>
      <p className="docs-lead">
        Instant, non-invasive checkers for every layer of your site&apos;s security — each grades
        your site A–F and hands you the exact fix. No account required.
      </p>
      <div className="tool-related-grid">
        {TOOLS.map((t) => (
          <Link href={`/tools/${t.slug}`} className="tool-card" key={t.slug}>
            <strong>{t.name}</strong>
            <span>{t.tagline}</span>
          </Link>
        ))}
      </div>
    </main>
  );
}
