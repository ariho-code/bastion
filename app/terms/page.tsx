import type { Metadata } from "next";
import { brand } from "@/lib/brand";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: `The terms for using ${brand.name}, including acceptable use of the scanner.`,
};

export default function TermsPage() {
  const updated = "July 2026";
  return (
    <main className="legal">
      <h1>Terms of Service</h1>
      <p className="legal-updated">Last updated: {updated}</p>

      <p>
        These Terms govern your use of {brand.name} (the &quot;Service&quot;). By using the Service, you
        agree to them. If you use the Service on behalf of an organization, you agree on its behalf.
      </p>

      <h2>1. What the Service does</h2>
      <p>
        {brand.name} performs non-invasive security analysis of publicly available information about a
        website — response headers, TLS certificate, public DNS records and similar signals — and returns a
        graded report with recommendations. The Service reads only what a normal browser receives; it does
        not attempt to exploit, brute-force, or gain unauthorized access to any system.
      </p>

      <h2>2. Acceptable use</h2>
      <p>
        You agree to use {brand.name} lawfully and responsibly. You must not use the Service to facilitate
        unauthorized access, to disguise attacks, to violate the rights of others, or in a manner that
        overloads or disrupts the Service or any third party. You are responsible for ensuring you have the
        right to scan a given site where your use requires it. Automated or bulk access outside the
        provided features requires a plan that includes API access.
      </p>

      <h2>3. No warranty; informational output</h2>
      <p>
        The Service is provided &quot;as is.&quot; A grade or report is a point-in-time, best-effort
        assessment of specific public signals and is <strong>not</strong> a guarantee that a site is secure
        or insecure, nor a substitute for a full security audit or penetration test. You are responsible for
        reviewing and testing any suggested fix before applying it to your systems.
      </p>

      <h2>4. Paid plans and billing</h2>
      <p>
        Paid features are billed through our payment provider acting as merchant of record. Subscriptions
        renew for the period you select until cancelled. You may cancel any time; access continues to the
        end of the current period. Paid plans include a 14-day money-back guarantee as described at
        checkout. Taxes may apply based on your location and are handled by the provider.
      </p>

      <h2>5. Intellectual property</h2>
      <p>
        The Service, including its software, design and content, is owned by {brand.name}. Reports you
        generate are yours to use. You may not copy, resell, or create a competing service from the Service
        itself without permission.
      </p>

      <h2>6. Limitation of liability</h2>
      <p>
        To the maximum extent permitted by law, {brand.name} is not liable for any indirect, incidental, or
        consequential damages, or for any loss arising from reliance on a report or from any security
        incident. Our total liability for any claim is limited to the amount you paid for the Service in the
        three months before the claim.
      </p>

      <h2>7. Termination</h2>
      <p>
        We may suspend or terminate access for violation of these Terms or misuse of the Service. You may
        stop using the Service at any time.
      </p>

      <h2>8. Changes</h2>
      <p>
        We may update these Terms as the Service evolves. Continued use after changes constitutes
        acceptance. Material changes will be reflected by the date above.
      </p>

      <h2>9. Contact</h2>
      <p>
        Questions about these Terms? Email <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a>.
      </p>
    </main>
  );
}
