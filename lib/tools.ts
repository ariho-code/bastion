export interface ToolFaq {
  q: string;
  a: string;
}

export interface Tool {
  slug: string;
  name: string;
  h1: string;
  tagline: string;
  keywords: string[];
  intro: string;
  sections: { h: string; p: string }[];
  bullets: { title: string; body: string }[];
  faqs: ToolFaq[];
}

/** Programmatic SEO landing pages — each targets a high-intent search term and
 *  funnels into the same live scanner. */
export const TOOLS: Tool[] = [
  {
    slug: "security-headers-checker",
    name: "Security Headers Checker",
    h1: "Free Security Headers Checker",
    tagline: "Grade any site's HTTP security headers A–F in seconds — with copy-paste fixes.",
    keywords: [
      "security headers checker",
      "http security headers",
      "check security headers",
      "security headers test",
    ],
    intro:
      "HTTP response headers are your website's first line of defense against XSS, clickjacking and content-sniffing attacks. This free checker inspects every important security header on your site and tells you exactly which are missing and how to add them.",
    sections: [
      {
        h: "Why HTTP security headers matter",
        p: "A single missing header can be the difference between a blocked attack and a full account takeover. Content-Security-Policy stops cross-site scripting, X-Frame-Options and frame-ancestors stop clickjacking, and X-Content-Type-Options stops MIME-sniffing. Browsers enforce these controls for free — you just have to send them.",
      },
      {
        h: "How the grade is calculated",
        p: "Each header is weighted by real-world impact, then scored against the maximum and mapped to an A–F letter grade. Every finding ships with a plain-English explanation and a ready-to-paste snippet for nginx, Apache, Express or your CDN, so you can fix issues in minutes and re-scan to confirm.",
      },
    ],
    bullets: [
      { title: "Content-Security-Policy", body: "Detects a missing or weakened CSP (unsafe-inline, wildcards, no object-src)." },
      { title: "X-Frame-Options / frame-ancestors", body: "Confirms clickjacking protection is in place." },
      { title: "X-Content-Type-Options", body: "Checks that MIME-sniffing is disabled with nosniff." },
      { title: "Referrer-Policy & Permissions-Policy", body: "Verifies referrer leakage and powerful-feature controls." },
    ],
    faqs: [
      {
        q: "What are HTTP security headers?",
        a: "They are response headers a server sends that instruct the browser to enforce protections — like Content-Security-Policy, Strict-Transport-Security, X-Frame-Options and X-Content-Type-Options. They are one of the cheapest, highest-impact security wins available.",
      },
      {
        q: "Which security headers are most important?",
        a: "Content-Security-Policy and Strict-Transport-Security (HSTS) have the biggest impact, followed by X-Content-Type-Options, X-Frame-Options (or CSP frame-ancestors), Referrer-Policy and Permissions-Policy.",
      },
      {
        q: "How do I add security headers?",
        a: "You set them in your web server (nginx add_header, Apache Header set), your app framework, or your CDN/edge config. Our scanner gives you the exact snippet for each missing header.",
      },
    ],
  },
  {
    slug: "hsts-checker",
    name: "HSTS Checker",
    h1: "Free HSTS Checker",
    tagline: "Check your Strict-Transport-Security header and max-age — and whether you're preload-ready.",
    keywords: ["hsts checker", "strict transport security", "hsts test", "hsts preload check"],
    intro:
      "HSTS (HTTP Strict Transport Security) forces browsers to only ever connect to your site over HTTPS, defeating protocol-downgrade and SSL-stripping attacks. This checker reads your HSTS header and flags a missing header, a short max-age, or missing includeSubDomains/preload.",
    sections: [
      {
        h: "What HSTS protects against",
        p: "Without HSTS, a visitor's first request can go over plain HTTP, where an attacker on the network can strip HTTPS and intercept the session. HSTS tells the browser to remember to always use HTTPS for a set duration, closing that window on every subsequent visit.",
      },
      {
        h: "Getting HSTS right",
        p: "Aim for a max-age of at least six months (ideally two years), add includeSubDomains once every subdomain supports HTTPS, and add preload to be baked into browsers. Our checker confirms each of these and gives you the exact header to deploy.",
      },
    ],
    bullets: [
      { title: "Header presence", body: "Detects whether Strict-Transport-Security is sent at all." },
      { title: "max-age strength", body: "Flags durations that are too short to be effective." },
      { title: "includeSubDomains", body: "Checks that subdomains are covered." },
      { title: "preload readiness", body: "Confirms your policy qualifies for the browser preload list." },
    ],
    faqs: [
      {
        q: "What is a good HSTS max-age?",
        a: "At least 15552000 seconds (180 days). For preload eligibility you need at least 31536000 (one year), plus includeSubDomains and the preload directive.",
      },
      {
        q: "Is HSTS preload safe?",
        a: "It's very effective but hard to undo quickly, so only add preload once you're certain every subdomain will serve HTTPS indefinitely.",
      },
      {
        q: "How do I enable HSTS?",
        a: "Send a Strict-Transport-Security header from your server or CDN, e.g. \"max-age=63072000; includeSubDomains; preload\". Our scanner shows the exact nginx/Apache snippet.",
      },
    ],
  },
  {
    slug: "csp-checker",
    name: "Content Security Policy Checker",
    h1: "Free Content Security Policy (CSP) Checker",
    tagline: "Analyze your CSP for XSS gaps — unsafe-inline, wildcards and missing directives.",
    keywords: ["csp checker", "content security policy checker", "csp test", "content-security-policy validator"],
    intro:
      "A Content-Security-Policy is the single most effective defense against cross-site scripting (XSS). This checker inspects your CSP and flags the weaknesses attackers look for: 'unsafe-inline', 'unsafe-eval', wildcard sources and a missing object-src.",
    sections: [
      {
        h: "Why CSP is your best anti-XSS control",
        p: "Even if a bug lets an attacker inject markup, a strict CSP stops the injected script from executing by restricting which sources the browser will run. It's defense-in-depth that works at the browser level, independent of your application code.",
      },
      {
        h: "Common CSP mistakes",
        p: "The most common failure is shipping a policy that still allows 'unsafe-inline' or 'unsafe-eval', which largely defeats the purpose. Wildcards (*) in script-src, and forgetting object-src 'none' and base-uri 'self', are close behind. Our checker calls out each of these.",
      },
    ],
    bullets: [
      { title: "unsafe-inline / unsafe-eval", body: "Flags directives that let injected scripts run." },
      { title: "Wildcard sources", body: "Detects overly-broad * sources in script/default-src." },
      { title: "object-src & base-uri", body: "Checks for the directives that block plugin and base-tag abuse." },
      { title: "frame-ancestors", body: "Confirms clickjacking protection via CSP." },
    ],
    faqs: [
      {
        q: "What makes a strong CSP?",
        a: "A strong CSP avoids 'unsafe-inline'/'unsafe-eval' (using nonces or hashes instead), avoids wildcards, and explicitly sets object-src 'none', base-uri 'self' and frame-ancestors.",
      },
      {
        q: "Will a CSP break my site?",
        a: "It can if configured too strictly at once. Start with Content-Security-Policy-Report-Only to observe violations, then enforce once clean.",
      },
      {
        q: "Does CSP replace input sanitization?",
        a: "No — it's defense-in-depth. Keep sanitizing and encoding output; CSP is the safety net if something slips through.",
      },
    ],
  },
  {
    slug: "ssl-tls-checker",
    name: "SSL/TLS Checker",
    h1: "Free SSL/TLS Checker",
    tagline: "Check your certificate, TLS version, forward secrecy and OCSP stapling.",
    keywords: ["ssl checker", "tls checker", "ssl certificate checker", "tls version test"],
    intro:
      "This SSL/TLS checker performs a live handshake with your server and reports the negotiated protocol, cipher, certificate validity and expiry, forward secrecy and OCSP stapling — everything you need to confirm your encryption is modern and healthy.",
    sections: [
      {
        h: "Beyond 'has a padlock'",
        p: "A valid certificate is table stakes. Real TLS health also means disabling legacy protocols (TLS 1.0/1.1), negotiating forward-secret ciphers so recorded traffic can't be decrypted later, and stapling OCSP so revocation checks are fast and private.",
      },
      {
        h: "Catch expiry before your users do",
        p: "Expired certificates cause full-page browser warnings that block virtually all visitors. Our checker reports days-to-expiry and the issuer so you can automate renewal well ahead of time.",
      },
    ],
    bullets: [
      { title: "Certificate validity", body: "Trust chain, issuer and days until expiry." },
      { title: "TLS protocol version", body: "Flags deprecated TLS 1.0/1.1; confirms TLS 1.2/1.3." },
      { title: "Forward secrecy", body: "Verifies (EC)DHE key exchange or TLS 1.3." },
      { title: "OCSP stapling & key strength", body: "Checks stapling and RSA/EC key strength." },
    ],
    faqs: [
      {
        q: "What TLS version should I use?",
        a: "TLS 1.2 as a minimum and TLS 1.3 where possible. TLS 1.0 and 1.1 are deprecated and should be disabled.",
      },
      {
        q: "What is forward secrecy?",
        a: "A property of the key exchange (ECDHE/DHE, and all of TLS 1.3) that ensures a future compromise of the server's private key can't decrypt previously recorded traffic.",
      },
      {
        q: "What is OCSP stapling?",
        a: "The server attaches a signed, cached proof that its certificate isn't revoked, so browsers don't have to make a slow, privacy-leaking call to the CA.",
      },
    ],
  },
  {
    slug: "dmarc-checker",
    name: "DMARC Checker",
    h1: "Free DMARC Checker",
    tagline: "Check your DMARC record and policy — and stop attackers spoofing your domain.",
    keywords: ["dmarc checker", "dmarc record check", "dmarc test", "dmarc lookup"],
    intro:
      "DMARC tells receiving mail servers what to do with email that fails SPF and DKIM — the key to stopping attackers from spoofing your domain in phishing. This checker looks up your DMARC record and reports whether it's missing, monitor-only (p=none), or actually enforcing.",
    sections: [
      {
        h: "Why p=none isn't enough",
        p: "Many domains publish DMARC but leave it at p=none, which only monitors and never blocks spoofed mail. Real protection means moving to p=quarantine and then p=reject once your legitimate senders are aligned.",
      },
      {
        h: "SPF, DKIM and DMARC together",
        p: "DMARC builds on SPF (which hosts may send) and DKIM (a cryptographic signature). Our full scan checks all three plus advanced controls like MTA-STS and BIMI, giving you the complete email-authentication picture.",
      },
    ],
    bullets: [
      { title: "Record presence", body: "Detects a missing _dmarc TXT record." },
      { title: "Policy strength", body: "Distinguishes p=none (monitor) from quarantine/reject (enforcing)." },
      { title: "Reporting", body: "Encourages rua reporting so you can watch alignment." },
      { title: "SPF & DKIM context", body: "Cross-checks the records DMARC depends on." },
    ],
    faqs: [
      {
        q: "What is a good DMARC policy?",
        a: "Aim for p=reject (or at least p=quarantine) with an rua reporting address, once you've confirmed your legitimate senders pass SPF and DKIM alignment.",
      },
      {
        q: "How do I set up DMARC?",
        a: "Publish a TXT record at _dmarc.yourdomain.com starting with \"v=DMARC1; p=none; rua=mailto:...\", monitor reports, then tighten to quarantine and reject.",
      },
      {
        q: "Does DMARC stop all spoofing?",
        a: "It stops spoofing of your exact domain in compliant inboxes. Combine it with SPF, DKIM and BIMI for the strongest protection.",
      },
    ],
  },
  {
    slug: "spf-checker",
    name: "SPF Checker",
    h1: "Free SPF Record Checker",
    tagline: "Look up and validate your SPF record to prevent email spoofing.",
    keywords: ["spf checker", "spf record check", "spf lookup", "spf test"],
    intro:
      "An SPF record lists which servers are allowed to send email for your domain, helping receiving servers reject spoofed mail. This checker looks up your SPF TXT record and confirms it exists and is well-formed.",
    sections: [
      {
        h: "What SPF does",
        p: "When a mail server receives a message claiming to be from your domain, it checks your SPF record to see whether the sending server is authorized. If not, the message can be rejected or marked as spam — reducing spoofing and improving your deliverability.",
      },
      {
        h: "SPF is only part of the story",
        p: "SPF alone can be bypassed via forwarding and doesn't cover the visible From address. That's why it works best alongside DKIM and DMARC. Our full scan checks all three together.",
      },
    ],
    bullets: [
      { title: "Record presence", body: "Detects whether an SPF (v=spf1) record exists." },
      { title: "Spoofing exposure", body: "Flags domains without SPF as easier to impersonate." },
      { title: "DMARC alignment", body: "Checks the DMARC policy that enforces SPF results." },
      { title: "Full email posture", body: "Includes DKIM, MTA-STS, TLS-RPT and BIMI." },
    ],
    faqs: [
      {
        q: "What does an SPF record look like?",
        a: "A TXT record on your root domain such as \"v=spf1 include:_spf.google.com ~all\", listing authorized senders and a policy (~all soft-fail or -all hard-fail).",
      },
      {
        q: "Should I use ~all or -all?",
        a: "-all (hard fail) is stronger but only safe once you're certain every legitimate sender is listed. ~all (soft fail) is a common, safer starting point.",
      },
      {
        q: "Why isn't SPF enough on its own?",
        a: "SPF breaks with forwarding and doesn't protect the visible From header. Pair it with DKIM and a DMARC policy for real protection.",
      },
    ],
  },
  {
    slug: "dnssec-checker",
    name: "DNSSEC Checker",
    h1: "Free DNSSEC Checker",
    tagline: "Check whether your domain is protected by DNSSEC against DNS spoofing.",
    keywords: ["dnssec checker", "dnssec test", "dnssec validation", "check dnssec"],
    intro:
      "DNSSEC cryptographically signs your DNS records so attackers can't forge them and silently redirect your visitors. This checker performs a validating DNS-over-HTTPS lookup and reports whether your domain's answers are DNSSEC-authenticated.",
    sections: [
      {
        h: "Why DNSSEC matters",
        p: "DNS was designed without authentication, so a network attacker or poisoned resolver can hand your visitors a fake IP address and send them to a malicious server. DNSSEC signs your zone so resolvers can verify answers are genuine and untampered.",
      },
      {
        h: "Enabling DNSSEC",
        p: "Most managed DNS providers offer one-click DNSSEC. After enabling it you add a DS record at your registrar to complete the chain of trust. Our checker confirms the authenticated (AD) flag is set on your responses.",
      },
    ],
    bullets: [
      { title: "Validation status", body: "Checks the authenticated-data (AD) flag via DNSSEC-aware resolvers." },
      { title: "Spoofing resistance", body: "Flags unsigned zones as vulnerable to cache poisoning." },
      { title: "CAA context", body: "Cross-checks certificate-authority restrictions." },
      { title: "Full DNS posture", body: "Part of a complete DNS & email security scan." },
    ],
    faqs: [
      {
        q: "How do I know if DNSSEC is enabled?",
        a: "A DNSSEC-aware resolver returns the AD (Authenticated Data) flag for your domain, and a DS record exists at your registrar. This checker verifies the AD flag for you.",
      },
      {
        q: "Does DNSSEC slow down my site?",
        a: "The overhead is negligible for visitors. The main effort is the one-time setup at your DNS provider and registrar.",
      },
      {
        q: "What does DNSSEC protect against?",
        a: "DNS cache poisoning and spoofing — attacks that forge DNS answers to redirect your users to malicious servers.",
      },
    ],
  },
  {
    slug: "cookie-security-checker",
    name: "Cookie Security Checker",
    h1: "Free Cookie Security Checker",
    tagline: "Check your cookies for Secure, HttpOnly and SameSite flags.",
    keywords: ["cookie security checker", "secure cookie test", "httponly samesite checker", "cookie flags"],
    intro:
      "Cookies carry sessions and tokens, so their flags matter. This checker inspects the Set-Cookie headers on your site and flags cookies missing Secure, HttpOnly or SameSite — the attributes that stop session hijacking, XSS theft and CSRF.",
    sections: [
      {
        h: "The three flags that matter",
        p: "Secure keeps cookies off unencrypted connections, HttpOnly hides them from JavaScript (blocking XSS theft), and SameSite limits cross-site sending (blocking CSRF). Session cookies without all three are a common, serious weakness.",
      },
      {
        h: "Getting cookie security right",
        p: "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies, and consider the __Host- prefix for the strongest guarantees. Our scanner reports exactly which cookies fall short.",
      },
    ],
    bullets: [
      { title: "Secure flag", body: "Ensures cookies are only sent over HTTPS." },
      { title: "HttpOnly flag", body: "Confirms cookies are hidden from JavaScript." },
      { title: "SameSite flag", body: "Checks cross-site sending is restricted." },
      { title: "Session safety", body: "Highlights auth cookies missing protections." },
    ],
    faqs: [
      {
        q: "What cookie flags should I set?",
        a: "For session cookies: Secure, HttpOnly and SameSite=Lax (or Strict). Consider the __Host- prefix and a sensible Path.",
      },
      {
        q: "What does HttpOnly do?",
        a: "It prevents client-side JavaScript from reading the cookie, which stops most cross-site scripting (XSS) attacks from stealing session tokens.",
      },
      {
        q: "What is SameSite?",
        a: "A flag that controls whether a cookie is sent on cross-site requests. Lax or Strict blocks most cross-site request forgery (CSRF).",
      },
    ],
  },
];

export function getTool(slug: string): Tool | undefined {
  return TOOLS.find((t) => t.slug === slug);
}
