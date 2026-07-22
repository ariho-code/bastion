import { brand, SITE_URL } from "@/lib/brand";
import { FAQS } from "@/lib/faqs";

export default function JsonLd() {
  const data = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "FAQPage",
        mainEntity: FAQS.map((f) => ({
          "@type": "Question",
          name: f.q,
          acceptedAnswer: { "@type": "Answer", text: f.a },
        })),
      },
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
        logo: `${SITE_URL}/brand/icon?size=512`,
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
