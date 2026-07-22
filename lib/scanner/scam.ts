/**
 * Lightweight scam / phishing heuristics for the free TypeScript scanner.
 * Mirrors the Go engine's pure detection path (no RDAP/blocklists here) so
 * every scan surface — free API, scam-check UI via deep engine, advanced —
 * speaks the same language about brand impersonation and kit patterns.
 */

import type { Finding, Severity, Status } from "./types";

export type ScamLevel = 0 | 1 | 2 | 3; // SAFE / LOW RISK / SUSPICIOUS / DANGEROUS

export interface ScamAssessment {
  score: number;
  level: ScamLevel;
  verdict: "SAFE" | "LOW RISK" | "SUSPICIOUS" | "DANGEROUS";
  brand: string | null;
  reasons: string[];
  findings: Finding[];
}

const BRANDS: { name: string; tokens: string[]; domains: string[] }[] = [
  { name: "PayPal", tokens: ["paypal"], domains: ["paypal.com"] },
  { name: "Binance", tokens: ["binance"], domains: ["binance.com", "binance.us"] },
  { name: "Coinbase", tokens: ["coinbase"], domains: ["coinbase.com"] },
  { name: "MetaMask", tokens: ["metamask"], domains: ["metamask.io"] },
  { name: "Microsoft", tokens: ["microsoft", "office365"], domains: ["microsoft.com", "office.com", "outlook.com", "live.com"] },
  { name: "Apple", tokens: ["apple", "icloud"], domains: ["apple.com", "icloud.com"] },
  { name: "Google", tokens: ["google", "gmail"], domains: ["google.com", "gmail.com"] },
  { name: "Amazon", tokens: ["amazon"], domains: ["amazon.com"] },
  { name: "Netflix", tokens: ["netflix"], domains: ["netflix.com"] },
  { name: "Facebook", tokens: ["facebook"], domains: ["facebook.com", "fb.com", "meta.com"] },
  { name: "WhatsApp", tokens: ["whatsapp"], domains: ["whatsapp.com"] },
  { name: "DHL", tokens: ["dhl"], domains: ["dhl.com"] },
  { name: "M-Pesa / Safaricom", tokens: ["mpesa", "safaricom"], domains: ["safaricom.co.ke"] },
  { name: "Flutterwave", tokens: ["flutterwave"], domains: ["flutterwave.com"] },
  { name: "Paystack", tokens: ["paystack"], domains: ["paystack.com"] },
];

const AFFIXES = [
  "login", "signin", "secure", "verify", "account", "update", "confirm", "support",
  "wallet", "official", "portal", "auth", "recovery", "alert", "claim", "reward",
];

const ABUSE_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click", "link", "cfd", "sbs",
  "icu", "cyou", "shop", "online", "site", "space", "fun", "pw", "cc",
]);

const SEED_MARKERS = [
  "seed phrase", "recovery phrase", "secret phrase", "mnemonic phrase",
  "12-word phrase", "24-word phrase", "enter your private key", "import your wallet",
  "restore your wallet", "your recovery phrase", "secret recovery phrase",
];

const SCAM_DOMAIN_TOKENS = [
  "aihub", "ai-hub", "aiprofit", "aitrade", "aitrading", "cryptoearn", "cryptohub",
  "forexbot", "tradebot", "investpro", "earnhub", "profitmax", "bitcoingive",
  "walletfix", "claimnow", "airdroplive", "futureai", "future-ai", "smartinvest",
];

const SCAM_DOMAIN_PARTS = [
  "ai", "hub", "earn", "profit", "invest", "trading", "trade", "forex", "crypto",
  "bitcoin", "btc", "wallet", "airdrop", "claim", "bot", "future", "wealth",
];

const PASSWORD_INPUT = /<input\b[^>]*\btype\s*=\s*["']?password\b/i;

const PRESENTATION = (tok: string) => [
  `sign in to ${tok}`, `log in to ${tok}`, `login to ${tok}`,
  `welcome to ${tok}`, `official ${tok}`, `${tok} account`, `${tok} security`,
  `verify your ${tok}`, `${tok} wallet`,
];

function secondLevel(domain: string): string {
  const i = domain.indexOf(".");
  return i > 0 ? domain.slice(0, i) : domain;
}

function isOfficial(domain: string): boolean {
  return BRANDS.some((b) => b.domains.includes(domain));
}

function boundaryContains(label: string, tok: string): boolean {
  let from = 0;
  while (from <= label.length) {
    const idx = label.indexOf(tok, from);
    if (idx < 0) return false;
    const beforeOK = idx === 0 || !/[a-z]/i.test(label[idx - 1]!);
    const end = idx + tok.length;
    const afterOK = end === label.length || !/[a-z]/i.test(label[end]!);
    if (beforeOK && afterOK) return true;
    from = idx + 1;
  }
  return false;
}

function affixConcat(label: string, tok: string): boolean {
  return AFFIXES.some((af) => label === tok + af || label === af + tok);
}

function stripTags(html: string): string {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ");
}

function detectImpersonation(host: string, domain: string, sld: string): { brand: string; weight: number } | null {
  let best: { brand: string; weight: number } | null = null;
  const keep = (brand: string, weight: number) => {
    if (!best || weight > best.weight) best = { brand, weight };
  };
  for (const b of BRANDS) {
    for (const od of b.domains) {
      if (host.includes(od + ".") && domain !== od && host.endsWith("." + domain.split(".").slice(-2).join("."))) {
        // subdomain deception: brand domain embedded as labels
        if (host.split(".").join(".").includes(od) && !host.endsWith(od)) {
          keep(b.name, 46);
        }
      }
      const labels = host.split(".");
      const odLabels = od.split(".");
      for (let i = 0; i + odLabels.length < labels.length; i++) {
        if (odLabels.every((l, j) => labels[i + j] === l)) {
          keep(b.name, 46);
        }
      }
    }
    for (const tok of b.tokens) {
      if (tok.length >= 4 && (boundaryContains(sld, tok) || affixConcat(sld, tok))) {
        keep(b.name, 35);
      }
      if (host.split(".").includes(tok) && secondLevel(domain) !== tok) {
        keep(b.name, 35);
      }
    }
  }
  return best;
}

function detectLexical(domain: string, sld: string): number {
  const flat = sld.replace(/-/g, "");
  for (const tok of SCAM_DOMAIN_TOKENS) {
    const tf = tok.replace(/-/g, "");
    if (tf.length >= 5 && (flat.includes(tf) || sld.includes(tok))) return 22;
  }
  const parts = sld.split(/[-_.]/);
  const hits = new Set<string>();
  for (const p of parts) {
    if (SCAM_DOMAIN_PARTS.includes(p)) hits.add(p);
  }
  for (const tok of SCAM_DOMAIN_PARTS) {
    if (tok.length >= 4 && flat.includes(tok)) hits.add(tok);
  }
  if (hits.size >= 2) return hits.size >= 3 ? 22 : 16;
  return 0;
}

function brandInContent(title: string, body: string): string | null {
  const visible = stripTags(body).slice(0, 20000).toLowerCase();
  const t = title.toLowerCase();
  for (const b of BRANDS) {
    for (const tok of b.tokens) {
      if (tok.length < 5) continue;
      if (boundaryContains(t, tok)) return b.name;
      for (const pat of PRESENTATION(tok)) {
        if (visible.includes(pat)) return b.name;
      }
    }
  }
  return null;
}

function scoreToLevel(score: number): ScamLevel {
  if (score >= 60) return 3;
  if (score >= 32) return 2;
  if (score >= 15) return 1;
  return 0;
}

const VERDICTS = ["SAFE", "LOW RISK", "SUSPICIOUS", "DANGEROUS"] as const;

/**
 * Assess a target for scam / phishing using pure heuristics on host + HTML.
 */
export function assessScam(opts: {
  host: string;
  domain: string;
  path?: string;
  html?: string;
  title?: string;
  scheme?: string;
}): ScamAssessment {
  const host = opts.host.toLowerCase();
  const domain = opts.domain.toLowerCase();
  const sld = secondLevel(domain);
  const path = (opts.path || "").toLowerCase();
  const body = (opts.html || "").toLowerCase();
  const title = (opts.title || "").toLowerCase();
  const reasons: string[] = [];
  let score = 0;
  let brand: string | null = null;

  const legit = isOfficial(domain);
  if (!legit) {
    const imp = detectImpersonation(host, domain, sld);
    if (imp) {
      brand = imp.brand;
      score += imp.weight;
      reasons.push(`The domain imitates ${imp.brand} but is not an official ${imp.brand} domain.`);
    }
  }

  const seed = SEED_MARKERS.some((m) => body.includes(m) || title.includes(m));
  if (seed) {
    score += 55;
    reasons.push("The page asks for a wallet recovery/seed phrase or private key.");
  }

  const lexical = detectLexical(domain, sld);
  if (lexical > 0) {
    score += lexical;
    reasons.push("The domain name matches patterns used by disposable investment/AI/crypto scam sites.");
  }

  const tld = domain.includes(".") ? domain.slice(domain.lastIndexOf(".") + 1) : "";
  if (ABUSE_TLDS.has(tld)) {
    score += 10;
    reasons.push("The domain uses a top-level domain frequently abused for throwaway scam sites.");
  }

  if (!legit) {
    const bc = brandInContent(title, body);
    if (bc && bc !== brand) {
      score += 20;
      reasons.push(`The page presents itself as ${bc}, but the domain is not owned by ${bc}.`);
      brand = brand || bc;
    }
  }

  const password = PASSWORD_INPUT.test(body);
  if (password && brand) {
    score += 18;
    reasons.push(`The page collects a password while impersonating ${brand}.`);
  }

  // Content playbooks (require 2+ phrase hits for the free path).
  const playbooks: { label: string; phrases: string[] }[] = [
    {
      label: "fake crypto giveaway",
      phrases: ["double your", "send 1 btc", "free bitcoin", "elon musk", "crypto giveaway", "bitcoin giveaway"],
    },
    {
      label: "fake investment scheme",
      phrases: ["guaranteed profit", "guaranteed returns", "double your money", "ai trading", "forex signals", "minimum deposit"],
    },
    {
      label: "account-suspension phishing",
      phrases: ["account has been suspended", "verify your identity", "unusual activity", "reactivate your account"],
    },
  ];
  const visible = stripTags(body);
  for (const pb of playbooks) {
    const hits = pb.phrases.filter((p) => visible.includes(p) || title.includes(p) || path.includes(p)).length;
    if (hits >= 2) {
      score += 12 + Math.min(10, hits * 3);
      reasons.push(`Content matches a known ${pb.label}.`);
    }
  }

  if (score > 100) score = 100;
  let level = scoreToLevel(score);
  if (seed) level = 3;
  if (brand && password) level = 3;
  if (lexical >= 16 && ABUSE_TLDS.has(tld) && level < 2) level = 2;

  const verdict = VERDICTS[level]!;
  const findings = buildFindings({ score, level, verdict, brand, reasons, seed, password, lexical });

  return { score, level, verdict, brand, reasons: reasons.slice(0, 6), findings };
}

function buildFindings(a: {
  score: number;
  level: ScamLevel;
  verdict: string;
  brand: string | null;
  reasons: string[];
  seed: boolean;
  password: boolean;
  lexical: number;
}): Finding[] {
  const out: Finding[] = [];

  // Impersonation
  if (a.brand) {
    out.push(f("phishing.impersonation", "Brand impersonation", "fail", "high", 0, 45,
      `This domain is impersonating ${a.brand}.`,
      "Do not enter login or payment details. Use a bookmark to reach the real site."));
  } else {
    out.push(f("phishing.impersonation", "Brand impersonation", "pass", "info", 45, 45,
      "The domain does not imitate any well-known brand."));
  }

  if (a.seed) {
    out.push(f("phishing.harvesting", "Credential & wallet harvesting", "fail", "critical", 0, 35,
      "This page asks for a wallet recovery/seed phrase. No legitimate wallet ever does this."));
  } else if (a.password && a.brand) {
    out.push(f("phishing.harvesting", "Credential & wallet harvesting", "fail", "high", 0, 35,
      `This page collects a password while impersonating ${a.brand}.`));
  } else {
    out.push(f("phishing.harvesting", "Credential & wallet harvesting", "pass", "info", 35, 35,
      "No wallet-draining or credential-harvesting patterns were detected."));
  }

  if (a.lexical > 0) {
    out.push(f("phishing.lexical", "Suspicious domain naming", a.level >= 2 ? "fail" : "warn",
      a.level >= 2 ? "high" : "medium", 0, 15,
      "The domain name matches patterns used by disposable investment/AI/crypto scam sites."));
  }

  const sev: Severity = a.level >= 3 ? "critical" : a.level >= 2 ? "high" : a.level >= 1 ? "low" : "info";
  const st: Status = a.level >= 2 ? "fail" : a.level >= 1 ? "warn" : "pass";
  const detail =
    a.level >= 3
      ? `DANGEROUS — strong scam indicators. Do not log in, pay, or connect a wallet. ${a.reasons[0] || ""}`
      : a.level >= 2
        ? `SUSPICIOUS — several red flags typical of scams. ${a.reasons[0] || ""}`
        : a.level >= 1
          ? `LOW RISK — a minor indicator was found. ${a.reasons[0] || ""}`
          : "SAFE — no scam or phishing indicators were detected on this site.";

  out.push(f("phishing.verdict", `Scam verdict: ${a.verdict}`, st, sev, 0, 0, detail));
  return out;
}

function f(
  id: string,
  title: string,
  status: Status,
  severity: Severity,
  points: number,
  maxPoints: number,
  detail: string,
  fix?: string
): Finding {
  return {
    id,
    category: "scam",
    title,
    status,
    severity,
    points,
    maxPoints,
    detail,
    fix,
  };
}
