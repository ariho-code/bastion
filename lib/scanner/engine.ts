import type { Finding, ScanResult } from "./types";
import {
  normalizeUrl,
  isBlockedHost,
  registrableDomain,
  fetchWithTimeout,
  inspectTls,
  resolveDns,
} from "./net";
import {
  checkHttps,
  checkRedirect,
  checkHsts,
  checkTls,
  checkCsp,
  checkClickjacking,
  checkNosniff,
  checkReferrer,
  checkPermissions,
  checkCrossOrigin,
  checkDns,
  checkCookies,
  checkServerBanner,
  checkPoweredBy,
  checkSecurityTxt,
  checkMethods,
} from "./checks";
import { scoreByCategory, gradeFromScore, sortFindings } from "./score";

export class ScanError extends Error {
  status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.status = status;
  }
}

function getSetCookies(headers: Headers): string[] {
  const any = headers as any;
  if (typeof any.getSetCookie === "function") return any.getSetCookie();
  const single = headers.get("set-cookie");
  return single ? [single] : [];
}

export async function runScan(rawInput: string): Promise<ScanResult> {
  const started = Date.now();

  if (!rawInput || typeof rawInput !== "string") {
    throw new ScanError("Please provide a URL to scan.");
  }

  let target: URL;
  try {
    target = new URL(normalizeUrl(rawInput));
  } catch {
    throw new ScanError("That doesn't look like a valid URL.");
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new ScanError("Only http and https URLs are supported.");
  }
  if (isBlockedHost(target.hostname)) {
    throw new ScanError("For safety, internal, local, and private addresses can't be scanned.");
  }

  const host = target.hostname;
  const domain = registrableDomain(host);
  const primaryUrl =
    target.protocol === "http:" ? "https://" + target.host + target.pathname : target.href;

  // Fire all network work concurrently.
  const mainReq = fetchWithTimeout(primaryUrl, { method: "GET", redirect: "follow" }, 12000).catch(
    async () => fetchWithTimeout(target.href, { method: "GET", redirect: "follow" }, 12000)
  );

  const redirectReq = (async (): Promise<boolean | null> => {
    try {
      const r = await fetchWithTimeout(
        "http://" + target.host + target.pathname,
        { method: "GET", redirect: "manual" },
        8000
      );
      const loc = r.headers.get("location") || "";
      if (r.status >= 300 && r.status < 400) return /^https:\/\//i.test(loc);
      if (r.status >= 200 && r.status < 300) return false;
      return null;
    } catch {
      return null;
    }
  })();

  const tlsReq = inspectTls(host).catch(() => null);
  const dnsReq = resolveDns(host, domain).catch(
    (): import("./types").DnsInfo => ({
      ip: undefined,
      hasMx: false,
      spf: null,
      dmarc: null,
      caa: false,
    })
  );

  const securityTxtReq = (async (): Promise<boolean> => {
    try {
      const r = await fetchWithTimeout(
        "https://" + target.host + "/.well-known/security.txt",
        { method: "GET" },
        7000
      );
      if (!r.ok) return false;
      const text = (await r.text()).slice(0, 4000);
      return /contact\s*:/i.test(text);
    } catch {
      return false;
    }
  })();

  const methodsReq = (async (): Promise<string | null> => {
    try {
      const r = await fetchWithTimeout(primaryUrl, { method: "OPTIONS" }, 7000);
      return r.headers.get("allow");
    } catch {
      return null;
    }
  })();

  const [res, redirectedToHttps, tls, dns, hasSecurityTxt, allow] = await Promise.all([
    mainReq,
    redirectReq,
    tlsReq,
    dnsReq,
    securityTxtReq,
    methodsReq,
  ]);

  if (!res) {
    throw new ScanError("Couldn't reach that site. Check the address and try again.", 502);
  }

  const headers = res.headers;
  const finalUrl = res.url || primaryUrl;
  const finalIsHttps = finalUrl.toLowerCase().startsWith("https://");
  const cookies = getSetCookies(headers);

  const findings: Finding[] = [
    checkHttps(finalIsHttps),
    checkRedirect(redirectedToHttps),
    checkHsts(headers),
    ...checkTls(tls),
    checkCsp(headers),
    checkClickjacking(headers),
    checkNosniff(headers),
    checkReferrer(headers),
    checkPermissions(headers),
    checkCrossOrigin(headers),
    ...checkDns(dns),
    checkServerBanner(headers),
    checkPoweredBy(headers),
    checkSecurityTxt(hasSecurityTxt),
    checkMethods(allow),
  ];

  const cookieFinding = checkCookies(cookies);
  if (cookieFinding) findings.push(cookieFinding);

  const { categories, overall } = scoreByCategory(findings);
  const grade = gradeFromScore(overall);
  const sorted = sortFindings(findings);

  const passed = findings.filter((f) => f.status === "pass").length;
  const warnings = findings.filter((f) => f.status === "warn").length;
  const failed = findings.filter((f) => f.status === "fail").length;

  return {
    url: rawInput,
    host,
    domain,
    finalUrl,
    grade,
    score: overall,
    categories,
    findings: sorted,
    meta: {
      server: headers.get("server") || undefined,
      poweredBy: headers.get("x-powered-by") || undefined,
      ip: dns.ip,
      tls: tls || undefined,
      email: { spf: !!dns.spf, dmarc: dns.dmarc ?? null, mx: dns.hasMx },
      redirectedToHttps: redirectedToHttps ?? undefined,
    },
    passed,
    warnings,
    failed,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
  };
}
