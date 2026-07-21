import type { Metadata } from "next";
import { brand } from "@/lib/brand";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: `How ${brand.name} handles data. We scan only public information and keep personal data to a minimum.`,
};

export default function PrivacyPage() {
  const updated = "July 2026";
  return (
    <main className="legal">
      <h1>Privacy Policy</h1>
      <p className="legal-updated">Last updated: {updated}</p>

      <p>
        {brand.name} (&quot;we&quot;, &quot;us&quot;) is a website security scanner. This policy explains
        what we collect, why, and the choices you have. We built {brand.name} to be privacy-respecting by
        default: scanning requires no account and collects no personal data about you.
      </p>

      <h2>1. What a scan collects</h2>
      <p>
        When you scan a URL, our server makes ordinary public requests to that address and reads only the
        information a normal browser receives — HTTP response headers, the TLS certificate, public DNS
        records (such as SPF, DMARC and CAA), and the presence of files like <code>security.txt</code>. We
        do not log in, submit forms, or attempt to access private areas of any site. Scan results are
        returned to your browser and are not tied to your identity.
      </p>

      <h2>2. Information stored in your browser</h2>
      <p>
        Your recent scan history and your cookie-consent choice are stored locally in your browser using
        <code> localStorage</code>. This data never leaves your device and is not sent to us. You can clear
        it any time from your browser settings.
      </p>

      <h2>3. Cookies and tracking</h2>
      <p>
        We use only essential storage required to operate the scanner and remember your preferences. We do
        not use advertising cookies or sell data to advertisers. If we later add privacy-friendly,
        aggregate analytics, we will update this policy and honor your consent choice.
      </p>

      <h2>4. Account and billing data (paid plans)</h2>
      <p>
        If you create an account or purchase a paid plan, we (and our payment provider acting as merchant
        of record) process the information needed to provide the service — such as your email address, the
        sites you choose to monitor, and billing details handled securely by the provider. We never store
        full card numbers. This information is used only to deliver and support the service.
      </p>

      <h2>5. How we use information</h2>
      <p>
        To run scans you request, provide monitoring and reports on paid plans, maintain security and
        prevent abuse, and communicate essential service updates. We do not sell your personal information.
      </p>

      <h2>6. Data retention</h2>
      <p>
        Anonymous scans are processed in memory to generate your report and are not retained as personal
        data. Account and monitoring data are retained while your account is active and deleted on request
        or a reasonable period after account closure.
      </p>

      <h2>7. Your rights</h2>
      <p>
        Depending on your location (including under the GDPR and CCPA), you may have rights to access,
        correct, export or delete your personal data. Contact us at{" "}
        <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a> and we will respond.
      </p>

      <h2>8. Children</h2>
      <p>{brand.name} is not directed to children under 13 and we do not knowingly collect their data.</p>

      <h2>9. Changes</h2>
      <p>
        We may update this policy as the product evolves. Material changes will be reflected by the &quot;last
        updated&quot; date above.
      </p>

      <h2>10. Contact</h2>
      <p>
        Questions? Email <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a>.
      </p>
    </main>
  );
}
