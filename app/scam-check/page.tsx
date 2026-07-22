import type { Metadata } from "next";
import ScamCheck from "@/components/ScamCheck";
import { brand, SITE_URL } from "@/lib/brand";

export const metadata: Metadata = {
  title: `Scam & Phishing Link Checker — Is This Website a Scam? | ${brand.name}`,
  description:
    "Free scam checker. Paste any link to instantly find out if a website is a scam or phishing site — crypto & wallet scams, fake shops, banking and mobile-money phishing. Get a clear SAFE or DANGEROUS verdict with reasons.",
  keywords: [
    "scam checker",
    "is this website a scam",
    "phishing link checker",
    "crypto scam checker",
    "website scam checker",
    "check if a link is safe",
    "fake website checker",
    "phishing website check",
  ],
  alternates: { canonical: `${SITE_URL}/scam-check` },
  openGraph: {
    title: `Is This Website a Scam? Free Scam & Phishing Checker — ${brand.name}`,
    description:
      "Paste a link and get an instant SAFE / SUSPICIOUS / DANGEROUS verdict. Detects brand impersonation, wallet-draining crypto scams, fake shops and phishing.",
    url: `${SITE_URL}/scam-check`,
  },
};

const FAQS = [
  {
    q: "How do I check if a website is a scam?",
    a: "Paste the website's link into the checker above and press Check now. We analyse the domain's age, whether it appears on abuse/phishing blocklists, whether it imitates a well-known brand (like PayPal, Binance or M-Pesa), and whether the page tries to harvest passwords or crypto wallet seed phrases — then give you a clear SAFE, SUSPICIOUS or DANGEROUS verdict with the reasons.",
  },
  {
    q: "How can I tell if a crypto link is a scam?",
    a: "The biggest red flag is any site asking for your wallet's recovery or seed phrase — no legitimate wallet or exchange EVER asks you to type it into a website. Others include brand-new domains, look-alike names (like 'metamask-connect') and fake giveaways or airdrops that promise to 'double' your crypto. Our checker flags all of these.",
  },
  {
    q: "What are the warning signs of a phishing site?",
    a: "Look-alike domains that imitate a real brand (paypa1.com, secure-paypal.xyz), a domain registered only days ago, a login page over plain HTTP, links that hide the real destination behind an '@' symbol or punycode, and urgent messages like 'your account is suspended, verify now'. The checker detects each of these automatically.",
  },
  {
    q: "Is the scam checker free?",
    a: "Yes. Checking a link is free and we don't store the links you check.",
  },
  {
    q: "It says DANGEROUS — what should I do?",
    a: "Do not enter any login details, card numbers, payment information or wallet access on the site, and leave it. If you already entered a password, change it on the real site immediately. If you entered a wallet seed phrase, move your funds to a brand-new wallet right away, because the old one should be considered compromised.",
  },
];

export default function ScamCheckPage() {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: FAQS.map((f) => ({
      "@type": "Question",
      name: f.q,
      acceptedAnswer: { "@type": "Answer", text: f.a },
    })),
  };

  return (
    <>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <main className="sc-page">
        <header className="sc-head">
          <span className="sc-badge">Free scam &amp; phishing checker</span>
          <h1 className="sc-title">
            Is this website <span className="sc-title-accent">a scam?</span>
          </h1>
          <p className="sc-lede">
            Paste any link and find out in seconds. We check the domain&apos;s age and reputation,
            whether it&apos;s pretending to be a brand you trust, and whether it&apos;s built to steal
            your password or crypto wallet — then tell you plainly whether it&apos;s safe.
          </p>
        </header>

        <ScamCheck />

        <section className="sc-signals">
          <h2>What we check</h2>
          <div className="sc-grid">
            <div className="sc-cell">
              <h3>Fake look-alikes</h3>
              <p>Domains imitating real brands — paypa1.com, secure-binance.xyz, mtn-momo-verify.top.</p>
            </div>
            <div className="sc-cell">
              <h3>Crypto &amp; wallet drainers</h3>
              <p>Pages that ask for a seed phrase or &quot;connect wallet&quot; to empty your funds, plus fake airdrops and giveaways.</p>
            </div>
            <div className="sc-cell">
              <h3>Brand-new domains</h3>
              <p>Most scam sites are only days old. We look up the real registration date via RDAP.</p>
            </div>
            <div className="sc-cell">
              <h3>Known-bad reputation</h3>
              <p>We cross-check reputable phishing and abuse blocklists (Spamhaus, SURBL).</p>
            </div>
            <div className="sc-cell">
              <h3>Password phishing</h3>
              <p>Login pages on look-alike domains, plain-HTTP logins, and &quot;verify your account&quot; traps.</p>
            </div>
            <div className="sc-cell">
              <h3>Local scams</h3>
              <p>Mobile-money PIN-reversal, lottery/prize wins and fake investment schemes — including scams common across Africa.</p>
            </div>
          </div>
        </section>

        <section className="sc-safety">
          <h2>How to protect yourself from scams</h2>
          <ul>
            <li>
              <strong>Never type your wallet seed / recovery phrase into any website.</strong> No real
              wallet or exchange will ever ask for it.
            </li>
            <li>
              <strong>Check the address bar carefully.</strong> Scammers use look-alikes like
              &quot;paypa1&quot; (with a number 1) or extra words like &quot;-secure-login&quot;.
            </li>
            <li>
              <strong>Slow down when a message is urgent.</strong> &quot;Your account will be closed&quot;
              and &quot;you&apos;ve won&quot; are pressure tactics to make you act before you think.
            </li>
            <li>
              <strong>Reach companies yourself.</strong> Type the real address or use the official app —
              don&apos;t click links in unexpected texts, emails or DMs.
            </li>
          </ul>
        </section>

        <section className="sc-faq">
          <span className="eyebrow">FAQ</span>
          <h2>Scam checker — frequently asked questions</h2>
          <div className="sc-faq-list">
            {FAQS.map((f) => (
              <details key={f.q} className="sc-faq-item">
                <summary>{f.q}</summary>
                <p>{f.a}</p>
              </details>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
