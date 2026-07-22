import type { Metadata } from "next";
import Link from "next/link";
import ScannerApp from "@/components/ScannerApp";
import Pricing from "@/components/Pricing";
import Faq from "@/components/Faq";
import Icon, { type IconName } from "@/components/Icon";
import T from "@/components/T";
import { brand } from "@/lib/brand";

const CAPABILITIES: { icon: IconName; title: string; body: string; href?: string }[] = [
  { icon: "gauge", title: "Instant A–F grade", body: "Paste a URL and get a full security report in seconds — no login, no install." },
  { icon: "shield-check", title: "28 deep checks", body: "TLS, response headers, DNSSEC, email authentication, cookies and live mixed-content." },
  { icon: "file-text", title: "Branded PDF reports", body: "Export a clean, client-ready PDF for any scan in a single click." },
  { icon: "send", title: "Email reports", body: "Send the full report and PDF straight to any inbox — free." },
  { icon: "bell", title: "Daily monitoring & alerts", body: "Auto re-scan your sites and get emailed the instant a grade drops." },
  { icon: "code", title: "REST API", body: "Automate scans in CI/CD and fail builds that fall below an A.", href: "/docs" },
];

type SearchParams = Record<string, string | string[] | undefined>;

const str = (v: string | string[] | undefined): string | undefined =>
  typeof v === "string" ? v : Array.isArray(v) ? v[0] : undefined;

/**
 * When a shared result link is opened (/?url=host&grade=A&score=95) we emit a
 * per-scan title and a dynamic Open Graph image so the link unfurls into a
 * branded "yoursite.com scored A" card on social platforms. Otherwise we fall
 * back to the site-wide defaults from the layout + opengraph-image.
 */
export function generateMetadata({
  searchParams,
}: {
  searchParams: SearchParams;
}): Metadata {
  const rawUrl = str(searchParams.url);
  const grade = str(searchParams.grade)?.toUpperCase().slice(0, 1);
  const score = str(searchParams.score)?.replace(/[^0-9]/g, "").slice(0, 3);
  if (!rawUrl || !grade || !/^[A-F]$/.test(grade)) return {};

  const host = rawUrl
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .slice(0, 64);
  const title = `${host} scored ${grade}${score ? ` (${score}/100)` : ""} on ${brand.name}`;
  const description = `See the full website security report for ${host} — TLS, security headers, DNS/email and cookies — graded A–F with copy-paste fixes.`;
  const ogImage = `/og?host=${encodeURIComponent(host)}&grade=${grade}${
    score ? `&score=${score}` : ""
  }`;

  return {
    title,
    description,
    openGraph: {
      title,
      description,
      images: [{ url: ogImage, width: 1200, height: 630 }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [ogImage],
    },
  };
}

const CATEGORIES: { icon: IconName; title: string; body: string }[] = [
  {
    icon: "lock",
    title: "Transport & TLS",
    body: "HTTPS enforcement, HTTP→HTTPS redirects, HSTS, the negotiated TLS version and full certificate validity — expiry, issuer and trust chain.",
  },
  {
    icon: "shield",
    title: "Response Headers",
    body: "Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and cross-origin isolation — your first line against XSS and clickjacking.",
  },
  {
    icon: "mail",
    title: "DNS & Email",
    body: "SPF, DMARC and CAA records so attackers can't spoof your domain in email or trick a CA into mis-issuing certificates.",
  },
  {
    icon: "cookie",
    title: "Cookies",
    body: "Every Set-Cookie is checked for Secure, HttpOnly and SameSite — the flags that stop session hijacking, XSS theft and CSRF.",
  },
  {
    icon: "eye",
    title: "Information Disclosure",
    body: "Leaky Server and X-Powered-By banners, risky HTTP methods, and whether you publish a security.txt for responsible disclosure.",
  },
  {
    icon: "file-text",
    title: "Actionable reports",
    body: "Every issue ships with a plain-English explanation and a copy-paste fix for nginx, Apache, Express or your DNS — exportable as a clean PDF.",
  },
];

const STEPS = [
  {
    n: "1",
    title: "Paste a URL",
    body: "Drop in any domain. No account, no install, no configuration.",
  },
  {
    n: "2",
    title: "We inspect it live",
    body: "Bastionscan runs 28 deep checks across TLS (forward secrecy, OCSP), headers, DNSSEC & email auth in seconds — reading only public data.",
  },
  {
    n: "3",
    title: "Fix and re-scan",
    body: "Get an A–F grade with prioritized fixes. Apply them, re-scan, and watch your score climb.",
  },
];

export default function Page() {
  return (
    <main>
      {/* Hero */}
      <section className="hero">
        <div className="hero-bg" aria-hidden="true">
          <div className="hero-aurora" />
          <div className="hero-grid" />
          <div className="hero-scan" />
          <div className="hero-vignette" />
        </div>
        <div className="hero-inner">
          <div className="badge">
            <span className="badge-dot" /> <T k="hero.badge" />
          </div>
          <h1>
            <T k="hero.title1" />{" "}
            <span className="grad">
              <T k="hero.accent" />
            </span>
            <br />
            <T k="hero.title2" />
          </h1>
          <p className="hero-sub">
            <T k="hero.sub" />
          </p>
          <ScannerApp />
          <div className="hero-trust">
            <span>
              <T k="hero.trust1" />
            </span>
            <span className="sep" />
            <span>
              <T k="hero.trust2" />
            </span>
            <span className="sep" />
            <span>
              <T k="hero.trust3" />
            </span>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="how">
        <div className="section-head">
          <span className="eyebrow">
            <T k="how.eyebrow" />
          </span>
          <h2>
            <T k="how.title" />
          </h2>
        </div>
        <div className="steps">
          {STEPS.map((s) => (
            <div key={s.n} className="step">
              <div className="step-n">{s.n}</div>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="features">
        <div className="section-head">
          <span className="eyebrow">
            <T k="feat.eyebrow" />
          </span>
          <h2>
            <T k="feat.title" />
          </h2>
          <p>
            <T k="feat.sub" />
          </p>
        </div>
        <div className="feature-grid">
          {CATEGORIES.map((c) => (
            <article key={c.title} className="feature">
              <div className="feature-icon" aria-hidden="true">
                <Icon name={c.icon} size={22} />
              </div>
              <h3>{c.title}</h3>
              <p>{c.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* Capabilities — what the product does */}
      <section id="platform" className="capabilities">
        <div className="section-head">
          <span className="eyebrow">
            <T k="plat.eyebrow" />
          </span>
          <h2>
            <T k="plat.title" />
          </h2>
          <p>
            <T k="plat.sub" />
          </p>
        </div>
        <div className="feature-grid">
          {CAPABILITIES.map((c) => {
            const inner = (
              <>
                <div className="feature-icon" aria-hidden="true">
                  <Icon name={c.icon} size={22} />
                </div>
                <h3>{c.title}</h3>
                <p>{c.body}</p>
                {c.href && <span className="feature-link">Learn more →</span>}
              </>
            );
            return c.href ? (
              <Link key={c.title} href={c.href} className="feature feature-link-card">
                {inner}
              </Link>
            ) : (
              <article key={c.title} className="feature">
                {inner}
              </article>
            );
          })}
        </div>
      </section>

      <Pricing />
      <Faq />

      {/* Final CTA */}
      <section className="final-cta">
        <div className="final-inner">
          <h2>
            <T k="final.title" />
          </h2>
          <p>
            <T k="final.sub" />
          </p>
          <a href="#scan" className="final-btn">
            <T k="final.btn" /> →
          </a>
        </div>
      </section>
    </main>
  );
}
