import { FAQS } from "@/lib/faqs";
import T from "@/components/T";

export default function Faq() {
  return (
    <section id="faq" className="faq">
      <div className="section-head">
        <span className="eyebrow">
          <T k="faq.eyebrow" />
        </span>
        <h2>
          <T k="faq.title" />
        </h2>
      </div>
      <div className="faq-list">
        {FAQS.map((f, i) => (
          <details key={i} className="faq-item">
            <summary>
              {f.q}
              <span className="faq-plus" aria-hidden="true" />
            </summary>
            <p>{f.a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}
