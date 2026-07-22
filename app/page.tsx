import type { Metadata } from "next";
import Link from "next/link";
import ScannerApp from "@/components/ScannerApp";
import Pricing from "@/components/Pricing";
import Faq from "@/components/Faq";
import Icon, { type IconName } from "@/components/Icon";
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
    body: "Bastion runs 28 deep checks across TLS (forward secrecy, OCSP), headers, DNSSEC & email auth in seconds — reading only public data.",
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
        <div className="hero-glow" aria-hidden="true" />
        <div className="hero-inner">
          <div className="badge">
            <span className="badge-dot" /> Trusted, non-invasive security scanning
          </div>
          <h1>
            Is your website <span className="grad">actually secure?</span>
            <br />
            Find out in seconds.
          </h1>
          <p className="hero-sub">
            {brand.name} grades any site A–F across TLS, security headers, DNS and cookies — then hands
            you the exact fixes. Free, instant, and safe to run on any website you own.
          </p>
          <ScannerApp />
          <div className="hero-trust">
            <span>28 deep security checks</span>
            <span className="sep" />
            <span>No login required</span>
            <span className="sep" />
            <span>Fixes for every issue</span>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="how">
        <div className="section-head">
          <span className="eyebrow">How it works</span>
          <h2>From URL to fixed in three steps</h2>
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
          <span className="eyebrow">What we check</span>
          <h2>A complete picture of your security posture</h2>
          <p>
            Most tools stop at a couple of headers. {brand.name} looks across five categories that
            actually determine whether your site can be attacked.
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
          <span className="eyebrow">The platform</span>
          <h2>Not just a scan — a security workflow</h2>
          <p>
            From a one-off check to continuous, automated protection across your whole portfolio —
            with reports your clients will actually read.
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
          <h2>Scan your site now — it&apos;s free</h2>
          <p>See your grade in seconds and get the fixes to reach an A.</p>
          <a href="#scan" className="final-btn">
            Run a free scan →
          </a>
        </div>
      </section>
    </main>
  );
}
