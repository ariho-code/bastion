import { FAQS } from "@/lib/faqs";

export default function Faq() {
  return (
    <section id="faq" className="faq">
      <div className="section-head">
        <span className="eyebrow">FAQ</span>
        <h2>Questions, answered</h2>
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
