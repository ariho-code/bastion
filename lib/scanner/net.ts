import tls from "node:tls";
import dnsp from "node:dns/promises";
import { parse } from "tldts";
import type { TlsInfo, DnsInfo } from "./types";

export function normalizeUrl(input: string): string {
  let u = input.trim().replace(/^['"]+|['"]+$/g, "");
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  return u;
}

export function registrableDomain(hostname: string): string {
  const p = parse(hostname);
  return p.domain || hostname;
}

/** Basic SSRF protection — refuse internal / private / loopback targets. */
export function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "0.0.0.0" || h === "::1" || h === "::") return true;
  if (/^127\./.test(h)) return true;
  if (/^10\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return true;
  if (/^169\.254\./.test(h)) return true;
  if (/^fe80:/i.test(h) || /^fc00:/i.test(h) || /^fd/i.test(h)) return true;
  return false;
}

const UA =
  "Mozilla/5.0 (compatible; BastionScanner/1.0; +https://bastionscan.com/bot) SecurityPostureCheck";

export async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  ms: number
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: { "User-Agent": UA, ...(options.headers || {}) },
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Inspect the TLS certificate, negotiated protocol, cipher, OCSP stapling. */
export function inspectTls(host: string, timeoutMs = 8000): Promise<TlsInfo | null> {
  return new Promise((resolve) => {
    let settled = false;
    let ocspStapled = false;
    const finish = (v: TlsInfo | null) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* noop */
      }
      resolve(v);
    };

    const connOpts: tls.ConnectionOptions & { requestOCSP?: boolean } = {
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: false, // inspect even invalid certs; we report validity ourselves
      requestOCSP: true,
      ALPNProtocols: ["h2", "http/1.1"],
    };

    const socket = tls.connect(
      connOpts,
      () => {
        try {
          const cert = socket.getPeerCertificate(true) as any;
          const protocol = socket.getProtocol() || undefined;
          const cipherName = socket.getCipher?.()?.name;
          const validTo = cert?.valid_to as string | undefined;
          let daysRemaining: number | undefined;
          if (validTo) {
            const end = new Date(validTo).getTime();
            if (!Number.isNaN(end)) {
              daysRemaining = Math.round((end - Date.now()) / 86400000);
            }
          }
          const san: string[] | undefined = cert?.subjectaltname
            ? String(cert.subjectaltname)
                .split(",")
                .map((s: string) => s.replace(/DNS:/gi, "").trim())
                .filter(Boolean)
            : undefined;

          const isEc = !!(cert?.nistCurve || cert?.asn1Curve);
          const keyType = isEc ? "EC" : cert?.bits ? "RSA" : undefined;
          const tls13 = /TLSv1\.3/i.test(protocol || "");
          const forwardSecrecy = tls13 || /ECDHE|DHE/i.test(cipherName || "");

          finish({
            protocol,
            cipher: cipherName,
            authorized: socket.authorized,
            authorizationError: (socket as any).authorizationError
              ? String((socket as any).authorizationError)
              : undefined,
            issuer: cert?.issuer?.O || cert?.issuer?.CN,
            subjectCN: cert?.subject?.CN,
            validFrom: cert?.valid_from,
            validTo,
            daysRemaining,
            san,
            keyBits: cert?.bits,
            keyType,
            forwardSecrecy,
            ocspStapled,
          });
        } catch {
          finish(null);
        }
      }
    );

    socket.on("OCSPResponse", (data: Buffer) => {
      if (data && data.length > 0) ocspStapled = true;
    });
    socket.setTimeout(timeoutMs, () => finish(null));
    socket.on("error", () => finish(null));
  });
}

/** DNSSEC validation via DNS-over-HTTPS (Cloudflare) — checks the AD flag. */
export async function resolveDnssec(host: string): Promise<boolean> {
  try {
    const r = await fetchWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&do=1`,
      { headers: { accept: "application/dns-json" } },
      5000
    );
    if (!r.ok) return false;
    const j: any = await r.json();
    return j?.AD === true;
  } catch {
    return false;
  }
}

export interface EmailAuth {
  mtaSts: boolean;
  tlsRpt: boolean;
  bimi: boolean;
  dkim: boolean;
  dkimSelector: string | null;
}

/** Advanced email-security posture: MTA-STS, TLS-RPT, BIMI, DKIM (common selectors). */
export async function resolveEmailAuth(domain: string): Promise<EmailAuth> {
  const selectors = ["default", "google", "selector1", "selector2", "k1", "mail"];

  const txt = (name: string) =>
    withTimeout(dnsp.resolveTxt(name).catch(() => [] as string[][]), 4000, [] as string[][]).then(
      flattenTxt
    );

  const [mtaTxt, mtaFileOk, tlsRptTxt, bimiTxt, dkimHits] = await Promise.all([
    txt("_mta-sts." + domain),
    (async () => {
      try {
        const r = await fetchWithTimeout(
          "https://mta-sts." + domain + "/.well-known/mta-sts.txt",
          {},
          4000
        );
        return r.ok;
      } catch {
        return false;
      }
    })(),
    txt("_smtp._tls." + domain),
    txt("default._bimi." + domain),
    Promise.all(
      selectors.map((s) =>
        txt(s + "._domainkey." + domain).then((recs) => ({
          s,
          found: recs.some((r) => /v=DKIM1|k=rsa|p=[A-Za-z0-9]/i.test(r)),
        }))
      )
    ),
  ]);

  const mtaSts = mtaTxt.some((r) => /v=STSv1/i.test(r)) || mtaFileOk;
  const tlsRpt = tlsRptTxt.some((r) => /v=TLSRPTv1/i.test(r));
  const bimi = bimiTxt.some((r) => /v=BIMI1/i.test(r));
  const dkimHit = dkimHits.find((d) => d.found);

  return {
    mtaSts,
    tlsRpt,
    bimi,
    dkim: !!dkimHit,
    dkimSelector: dkimHit ? dkimHit.s : null,
  };
}

async function withTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  const timeout = new Promise<T>((res) => {
    t = setTimeout(() => res(fallback), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(t!);
  }
}

function flattenTxt(records: string[][]): string[] {
  return records.map((chunks) => chunks.join(""));
}

/** Resolve DNS-based signals: A record, MX presence, SPF, DMARC policy, CAA. */
export async function resolveDns(host: string, domain: string): Promise<DnsInfo> {
  const [ips, mx, txt, dmarcTxt, caa] = await Promise.all([
    withTimeout(dnsp.resolve4(host).catch(() => [] as string[]), 4000, [] as string[]),
    withTimeout(dnsp.resolveMx(domain).catch(() => [] as any[]), 4000, [] as any[]),
    withTimeout(dnsp.resolveTxt(domain).catch(() => [] as string[][]), 4000, [] as string[][]),
    withTimeout(
      dnsp.resolveTxt("_dmarc." + domain).catch(() => [] as string[][]),
      4000,
      [] as string[][]
    ),
    withTimeout(dnsp.resolveCaa(domain).catch(() => [] as any[]), 4000, [] as any[]),
  ]);

  const txtFlat = flattenTxt(txt);
  const spf = txtFlat.find((r) => /^v=spf1/i.test(r.trim())) || null;
  const dmarcFlat = flattenTxt(dmarcTxt);
  const dmarc = dmarcFlat.find((r) => /^v=DMARC1/i.test(r.trim())) || null;

  return {
    ip: ips[0],
    hasMx: Array.isArray(mx) && mx.length > 0,
    spf,
    dmarc,
    caa: Array.isArray(caa) && caa.length > 0,
  };
}
