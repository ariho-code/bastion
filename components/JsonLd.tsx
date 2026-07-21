import { brand, SITE_URL } from "@/lib/brand";

export default function JsonLd() {
  const data = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebApplication",
        name: brand.name,
        url: SITE_URL,
        applicationCategory: "SecurityApplication",
        operatingSystem: "Any",
        description: brand.longDescription,
        offers: {
          "@type": "Offer",
          price: "0",
          priceCurrency: "USD",
          description: "Free unlimited website security scanning with A–F grading and fixes.",
        },
        featureList: [
          "Security headers analysis",
          "TLS/SSL certificate check",
          "HSTS and HTTPS validation",
          "Content Security Policy analysis",
          "SPF and DMARC email spoofing checks",
          "Cookie security flags",
          "PDF security report export",
        ],
      },
      {
        "@type": "Organization",
        name: brand.name,
        url: SITE_URL,
        email: brand.contactEmail,
      },
    ],
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  );
}
