import type { Metadata } from "next";
import AdvancedScanner from "@/components/AdvancedScanner";
import { brand, SITE_URL } from "@/lib/brand";

export const metadata: Metadata = {
  title: `Advanced Deep Scan — ${brand.name}`,
  description:
    "Go beyond headers. A concurrent Go scanning engine and Python risk brain run deep TLS/cipher analysis, attack-surface mapping, exposed-file probing and threat intelligence — then prioritize the fixes.",
  alternates: { canonical: `${SITE_URL}/advanced` },
  openGraph: {
    title: `Advanced Deep Scan — ${brand.name}`,
    description:
      "Deep TLS analysis, attack-surface mapping, exposed-file probing and threat intelligence, with a prioritized remediation roadmap.",
    url: `${SITE_URL}/advanced`,
  },
};

const CAPABILITIES = [
  { t: "Deep TLS & ciphers", d: "Live protocol + cipher-suite enumeration, full chain validation, forward secrecy." },
  { t: "Attack-surface mapping", d: "Port/service scan, subdomain discovery, technology & WAF fingerprinting." },
  { t: "Exposed-file probing", d: "Detects leaked .git, .env, backups and debug endpoints — content-validated." },
  { t: "Threat intelligence", d: "ASN/hosting, IP reputation across abuse blocklists, reverse DNS." },
  { t: "DNS & email auth", d: "SPF, DMARC, DKIM, CAA and DNSSEC over DNS-over-HTTPS." },
  { t: "Risk brain", d: "A Python service scores risk and builds a prioritized, effort-aware fix roadmap." },
];

export default function AdvancedPage() {
  return (
    <>
      <main className="av-page">
        <header className="av-head">
          <span className="av-badge">Advanced engine · Go + Python</span>
          <h1 className="av-title">
            Deep security analysis, <span className="av-title-accent">graded and prioritized</span>
          </h1>
          <p className="av-lede">
            The standard scan reads what a browser sees. This one goes deeper: a concurrent Go
            scanning engine actively probes transport, attack surface and exposure, while a Python
            risk brain turns the findings into a prioritized remediation plan.
          </p>
        </header>

        <AdvancedScanner />

        <section className="av-caps">
          {CAPABILITIES.map((c) => (
            <div className="av-cap" key={c.t}>
              <h3>{c.t}</h3>
              <p>{c.d}</p>
            </div>
          ))}
        </section>

        <p className="av-note">
          Deep scans actively connect to the target (TLS handshakes, common-port checks, well-known
          path requests). Only scan systems you own or are authorized to test.
        </p>
      </main>
    </>
  );
}
