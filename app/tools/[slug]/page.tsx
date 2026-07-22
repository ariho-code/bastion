import type { Metadata } from "next";
import { notFound } from "next/navigation";
import Link from "next/link";
import ScannerApp from "@/components/ScannerApp";
import Icon from "@/components/Icon";
import { TOOLS, getTool } from "@/lib/tools";
import { SITE_URL } from "@/lib/brand";

export function generateStaticParams() {
  return TOOLS.map((t) => ({ slug: t.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }): Metadata {
  const tool = getTool(params.slug);
  if (!tool) return {};
  const title = `${tool.name} — Free & Instant`;
  return {
    title,
    description: tool.tagline,
    keywords: tool.keywords,
    alternates: { canonical: `/tools/${tool.slug}` },
    openGraph: {
      title,
      description: tool.tagline,
      url: `${SITE_URL}/tools/${tool.slug}`,
      type: "website",
    },
  };
}

export default function ToolPage({ params }: { params: { slug: string } }) {
  const tool = getTool(params.slug);
  if (!tool) notFound();

  const related = TOOLS.filter((t) => t.slug !== tool.slug).slice(0, 4);
  const faqLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: tool.faqs.map((f) => ({
      "@type": "Question",
      name: f.q,
      acceptedAnswer: { "@type": "Answer", text: f.a },
    })),
  };

  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqLd) }}
      />

      <section className="hero tool-hero">
        <div className="hero-glow" aria-hidden="true" />
        <div className="hero-inner">
          <div className="tool-crumb">
            <Link href="/tools">Free tools</Link>
            <span>/</span>
            {tool.name}
          </div>
          <h1>{tool.h1}</h1>
          <p className="hero-sub">{tool.tagline}</p>
          <ScannerApp />
        </div>
      </section>

      <section className="tool-body">
        {tool.sections.map((s) => (
          <div className="tool-section" key={s.h}>
            <h2>{s.h}</h2>
            <p>{s.p}</p>
          </div>
        ))}

        <div className="tool-bullets">
          {tool.bullets.map((b) => (
            <div className="tool-bullet" key={b.title}>
              <span className="tool-bullet-icon">
                <Icon name="check" size={15} />
              </span>
              <div>
                <strong>{b.title}</strong>
                <span>{b.body}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="faq">
        <div className="section-head">
          <span className="eyebrow">FAQ</span>
          <h2>{tool.name} — FAQ</h2>
        </div>
        <div className="faq-list">
          {tool.faqs.map((f, i) => (
            <details className="faq-item" key={i}>
              <summary>
                {f.q}
                <span className="faq-plus" aria-hidden="true" />
              </summary>
              <p>{f.a}</p>
            </details>
          ))}
        </div>
      </section>

      <section className="tool-related">
        <div className="section-head">
          <span className="eyebrow">More free tools</span>
          <h2>Keep securing your stack</h2>
        </div>
        <div className="tool-related-grid">
          {related.map((r) => (
            <Link href={`/tools/${r.slug}`} className="tool-card" key={r.slug}>
              <strong>{r.name}</strong>
              <span>{r.tagline}</span>
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
