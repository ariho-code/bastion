import type { Finding, TlsInfo, DnsInfo, MixedContent } from "./types";

const H = (headers: Headers, name: string) => headers.get(name) ?? "";

// ---------- Transport ----------

export function checkHttps(finalIsHttps: boolean): Finding {
  return finalIsHttps
    ? {
        id: "https",
        category: "transport",
        title: "Served over HTTPS",
        status: "pass",
        points: 15,
        maxPoints: 15,
        severity: "critical",
        detail: "The site is served over an encrypted HTTPS connection — the baseline for any modern site.",
      }
    : {
        id: "https",
        category: "transport",
        title: "Not served over HTTPS",
        status: "fail",
        points: 0,
        maxPoints: 15,
        severity: "critical",
        detail:
          "This page loads over plain HTTP. Anyone on the network path can read or tamper with the traffic, including login credentials and payment data.",
        fix: "Install a TLS certificate (free via Let's Encrypt or your host's one-click SSL) and serve every page over https://.",
      };
}

export function checkRedirect(redirectedToHttps: boolean | null): Finding {
  if (redirectedToHttps === true) {
    return {
      id: "http-redirect",
      category: "transport",
      title: "HTTP redirects to HTTPS",
      status: "pass",
      points: 10,
      maxPoints: 10,
      severity: "high",
      detail: "Visitors who type http:// are automatically upgraded to the secure version.",
    };
  }
  if (redirectedToHttps === false) {
    return {
      id: "http-redirect",
      category: "transport",
      title: "HTTP does not force HTTPS",
      status: "fail",
      points: 0,
      maxPoints: 10,
      severity: "high",
      detail:
        "The plain-HTTP version serves content instead of redirecting to HTTPS, so users can land on an insecure page that attackers can hijack.",
      fix: `# nginx — force all HTTP to HTTPS\nserver {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}`,
    };
  }
  return {
    id: "http-redirect",
    category: "transport",
    title: "HTTP → HTTPS redirect not confirmed",
    status: "info",
    points: 0,
    maxPoints: 0,
    severity: "info",
    detail:
      "The plain-HTTP endpoint didn't respond in a way we could measure (often means the site is HTTPS-only, which is fine).",
  };
}

export function checkHsts(headers: Headers): Finding {
  const hsts = H(headers, "strict-transport-security");
  if (!hsts) {
    return {
      id: "hsts",
      category: "transport",
      title: "Missing HSTS",
      status: "fail",
      points: 0,
      maxPoints: 15,
      severity: "high",
      detail:
        "No Strict-Transport-Security header. Without it, a first visit over HTTP — or an attacker stripping HTTPS — can silently downgrade the connection.",
      fix: `# nginx\nadd_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n\n# Apache\nHeader always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"`,
      reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    };
  }
  const maxAge = parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || "0", 10);
  const strong = maxAge >= 15552000; // ~180 days
  return {
    id: "hsts",
    category: "transport",
    title: strong ? "HSTS enabled" : "HSTS max-age is too short",
    status: strong ? "pass" : "warn",
    points: strong ? 15 : 8,
    maxPoints: 15,
    severity: "high",
    evidence: hsts,
    detail: strong
      ? `Strict-Transport-Security forces HTTPS for future visits (max-age=${maxAge}s).`
      : `HSTS is set but max-age=${maxAge}s is short. Aim for at least 6 months so browsers reliably remember to use HTTPS.`,
    fix: strong
      ? undefined
      : `# nginx\nadd_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
  };
}

export function checkTls(tls: TlsInfo | null): Finding[] {
  if (!tls) {
    return [
      {
        id: "tls-protocol",
        category: "transport",
        title: "TLS details unavailable",
        status: "info",
        points: 0,
        maxPoints: 0,
        severity: "info",
        detail: "We couldn't complete a direct TLS handshake to inspect the certificate and protocol.",
      },
    ];
  }

  const findings: Finding[] = [];
  const proto = tls.protocol || "";
  const modern = /TLSv1\.[23]/i.test(proto);
  const legacy = /TLSv1(\.[01])?$/i.test(proto) && !modern;

  findings.push({
    id: "tls-protocol",
    category: "transport",
    title: modern ? `Modern TLS (${proto})` : legacy ? `Outdated TLS (${proto})` : "TLS protocol",
    status: modern ? "pass" : legacy ? "fail" : "info",
    points: modern ? 8 : 0,
    maxPoints: proto ? 8 : 0,
    severity: legacy ? "high" : "low",
    evidence: [proto, tls.cipher].filter(Boolean).join(" · "),
    detail: modern
      ? `The server negotiated ${proto}${tls.cipher ? ` with ${tls.cipher}` : ""}. TLS 1.2+ is current and secure.`
      : legacy
      ? `The server negotiated ${proto}, which is deprecated and vulnerable. Disable TLS 1.0/1.1 and require TLS 1.2 or 1.3.`
      : "Could not determine the negotiated TLS version.",
    fix: legacy
      ? `# nginx — require modern TLS only\nssl_protocols TLSv1.2 TLSv1.3;`
      : undefined,
  });

  // Certificate validity
  const err = (tls.authorizationError || "").toLowerCase();
  const expired = err.includes("expired") || (typeof tls.daysRemaining === "number" && tls.daysRemaining < 0);
  const untrusted =
    tls.authorized === false && !expired && (err.includes("self") || err.includes("unable") || err.includes("chain"));
  const expiringSoon = typeof tls.daysRemaining === "number" && tls.daysRemaining >= 0 && tls.daysRemaining < 15;

  let certStatus: Finding["status"] = "pass";
  let certPoints = 7;
  let certTitle = "Valid TLS certificate";
  let certDetail = `Issued by ${tls.issuer || "a trusted CA"}${
    typeof tls.daysRemaining === "number" ? `, ${tls.daysRemaining} days until expiry` : ""
  }.`;
  let certFix: string | undefined;
  let certSeverity: Finding["severity"] = "info";

  if (expired) {
    certStatus = "fail";
    certPoints = 0;
    certTitle = "Expired TLS certificate";
    certDetail = "The certificate has expired. Browsers will show a full-page security warning and block most visitors.";
    certFix = "Renew the certificate immediately (enable auto-renewal, e.g. certbot renew, to prevent recurrence).";
    certSeverity = "critical";
  } else if (untrusted) {
    certStatus = "fail";
    certPoints = 0;
    certTitle = "Untrusted TLS certificate";
    certDetail = `The certificate chain didn't validate (${tls.authorizationError}). Visitors will see a security warning.`;
    certFix = "Install a certificate from a trusted CA and include the full intermediate chain.";
    certSeverity = "high";
  } else if (expiringSoon) {
    certStatus = "warn";
    certPoints = 4;
    certTitle = "TLS certificate expiring soon";
    certDetail = `The certificate expires in ${tls.daysRemaining} day(s). Renew now to avoid an outage.`;
    certFix = "Enable automatic renewal so certificates rotate well before expiry.";
    certSeverity = "medium";
  }

  findings.push({
    id: "tls-cert",
    category: "transport",
    title: certTitle,
    status: certStatus,
    points: certPoints,
    maxPoints: 7,
    severity: certSeverity,
    evidence: tls.validTo ? `Expires ${tls.validTo}` : undefined,
    detail: certDetail,
    fix: certFix,
  });

  return findings;
}

// ---------- Response Headers ----------

export function checkCsp(headers: Headers): Finding {
  const csp = H(headers, "content-security-policy");
  if (csp) {
    const unsafe = /'unsafe-inline'|'unsafe-eval'/i.test(csp);
    const wildcard = /\b(?:default|script)-src\b[^;]*(?:\s|;|^)\*(?:\s|;|$)/i.test(csp);
    const noObjectSrc =
      !/object-src/i.test(csp) && !/default-src\s+[^;]*'none'/i.test(csp);
    const weak = unsafe || wildcard;
    const issues: string[] = [];
    if (unsafe) issues.push("allows 'unsafe-inline'/'unsafe-eval'");
    if (wildcard) issues.push("uses a wildcard (*) source");
    if (noObjectSrc) issues.push("no object-src 'none'");
    return {
      id: "csp",
      category: "headers",
      title: weak ? "CSP set (weakened directives)" : "Content-Security-Policy set",
      status: weak ? "warn" : "pass",
      points: weak ? 11 : 15,
      maxPoints: 15,
      severity: "high",
      evidence: issues.length ? issues.join("; ") : undefined,
      detail: weak
        ? `A CSP is present but it ${issues.join(
            ", "
          )}, which weakens its protection against XSS. Tighten it with nonces/hashes and explicit source lists.`
        : "A Content-Security-Policy is in place — the strongest defense against cross-site scripting (XSS) and injection.",
    };
  }
  return {
    id: "csp",
    category: "headers",
    title: "Missing Content-Security-Policy",
    status: "fail",
    points: 0,
    maxPoints: 15,
    severity: "high",
    detail:
      "No CSP header. A Content-Security-Policy is the single most effective control against XSS, restricting which scripts, styles, and resources may load.",
    fix: `# Start restrictive, then loosen only what you need (nginx):\nadd_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;`,
    reference: "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
  };
}

export function checkClickjacking(headers: Headers): Finding {
  const xfo = H(headers, "x-frame-options");
  const csp = H(headers, "content-security-policy");
  const frameAncestors = /frame-ancestors/i.test(csp);
  if (xfo || frameAncestors) {
    return {
      id: "clickjacking",
      category: "headers",
      title: "Clickjacking protection present",
      status: "pass",
      points: 10,
      maxPoints: 10,
      severity: "medium",
      detail: frameAncestors
        ? "CSP frame-ancestors restricts who can embed this site in a frame."
        : `X-Frame-Options (${xfo}) blocks the page from being embedded in malicious frames.`,
    };
  }
  return {
    id: "clickjacking",
    category: "headers",
    title: "No clickjacking protection",
    status: "fail",
    points: 0,
    maxPoints: 10,
    severity: "medium",
    detail:
      "Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in an invisible frame to trick users into clicking (clickjacking).",
    fix: `# nginx\nadd_header X-Frame-Options "DENY" always;   # or SAMEORIGIN\n# Preferred modern equivalent lives in your CSP:\n#   Content-Security-Policy: frame-ancestors 'none';`,
  };
}

export function checkNosniff(headers: Headers): Finding {
  const v = H(headers, "x-content-type-options");
  if (/nosniff/i.test(v)) {
    return {
      id: "nosniff",
      category: "headers",
      title: "MIME-sniffing disabled",
      status: "pass",
      points: 8,
      maxPoints: 8,
      severity: "medium",
      detail: "X-Content-Type-Options: nosniff stops browsers from guessing (and mis-executing) content types.",
    };
  }
  return {
    id: "nosniff",
    category: "headers",
    title: "Missing X-Content-Type-Options",
    status: "fail",
    points: 0,
    maxPoints: 8,
    severity: "low",
    detail: "Without nosniff, a browser may interpret a file as a different type than intended, enabling some attacks.",
    fix: `# nginx\nadd_header X-Content-Type-Options "nosniff" always;`,
  };
}

export function checkReferrer(headers: Headers): Finding {
  const v = H(headers, "referrer-policy");
  if (v) {
    return {
      id: "referrer",
      category: "headers",
      title: "Referrer-Policy set",
      status: "pass",
      points: 6,
      maxPoints: 6,
      severity: "low",
      evidence: v,
      detail: `Referrer-Policy (${v}) controls how much URL information leaks to other sites.`,
    };
  }
  return {
    id: "referrer",
    category: "headers",
    title: "Missing Referrer-Policy",
    status: "warn",
    points: 0,
    maxPoints: 6,
    severity: "low",
    detail: "No Referrer-Policy. Full URLs — which may hold sensitive path or query data — can leak to third parties.",
    fix: `# nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
  };
}

export function checkPermissions(headers: Headers): Finding {
  const v = H(headers, "permissions-policy") || H(headers, "feature-policy");
  if (v) {
    return {
      id: "permissions",
      category: "headers",
      title: "Permissions-Policy set",
      status: "pass",
      points: 5,
      maxPoints: 5,
      severity: "low",
      detail: "Permissions-Policy limits access to powerful browser features (camera, microphone, geolocation, etc.).",
    };
  }
  return {
    id: "permissions",
    category: "headers",
    title: "Missing Permissions-Policy",
    status: "warn",
    points: 0,
    maxPoints: 5,
    severity: "low",
    detail: "No Permissions-Policy. Explicitly disable browser features your site doesn't use to shrink its attack surface.",
    fix: `# nginx\nadd_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()" always;`,
  };
}

export function checkCrossOrigin(headers: Headers): Finding {
  const coop = H(headers, "cross-origin-opener-policy");
  const corp = H(headers, "cross-origin-resource-policy");
  const present = [coop, corp].filter(Boolean).length;
  if (present >= 1) {
    return {
      id: "cross-origin",
      category: "headers",
      title: "Cross-origin isolation headers present",
      status: "pass",
      points: 3,
      maxPoints: 3,
      severity: "info",
      detail: "COOP/CORP headers help isolate your site from cross-origin attacks like Spectre and tab-nabbing.",
    };
  }
  return {
    id: "cross-origin",
    category: "headers",
    title: "No cross-origin isolation headers",
    status: "warn",
    points: 0,
    maxPoints: 3,
    severity: "low",
    detail: "Consider Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy for defense-in-depth against cross-origin leaks.",
    fix: `# nginx\nadd_header Cross-Origin-Opener-Policy "same-origin" always;\nadd_header Cross-Origin-Resource-Policy "same-origin" always;`,
  };
}

// ---------- DNS & Email ----------

export function checkDns(dns: DnsInfo): Finding[] {
  const findings: Finding[] = [];

  // SPF
  findings.push(
    dns.spf
      ? {
          id: "spf",
          category: "dns",
          title: "SPF record found",
          status: "pass",
          points: 8,
          maxPoints: 8,
          severity: "medium",
          detail: "An SPF record tells receiving mail servers which hosts may send email for this domain, reducing spoofing.",
        }
      : {
          id: "spf",
          category: "dns",
          title: "No SPF record",
          status: "warn",
          points: 0,
          maxPoints: 8,
          severity: "medium",
          detail: "No SPF record. Attackers can more easily spoof email that appears to come from your domain.",
          fix: `# Add a DNS TXT record on your root domain, e.g.:\n"v=spf1 include:_spf.google.com ~all"`,
        }
  );

  // DMARC
  if (dns.dmarc) {
    const policy = (dns.dmarc.match(/p=([a-z]+)/i) || [])[1]?.toLowerCase() || "none";
    const enforcing = policy === "quarantine" || policy === "reject";
    findings.push({
      id: "dmarc",
      category: "dns",
      title: enforcing ? `DMARC enforced (p=${policy})` : "DMARC set to monitor only (p=none)",
      status: enforcing ? "pass" : "warn",
      points: enforcing ? 10 : 5,
      maxPoints: 10,
      severity: "medium",
      detail: enforcing
        ? "DMARC is published and enforcing, instructing mailboxes to quarantine or reject spoofed mail."
        : "DMARC exists but p=none only monitors. Move to p=quarantine, then p=reject, once your legitimate senders pass.",
      fix: enforcing
        ? undefined
        : `# Update the _dmarc TXT record once senders are aligned:\n"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"`,
    });
  } else {
    findings.push({
      id: "dmarc",
      category: "dns",
      title: "No DMARC record",
      status: "fail",
      points: 0,
      maxPoints: 10,
      severity: "medium",
      detail:
        "No DMARC record. DMARC ties SPF and DKIM together and tells mailboxes what to do with spoofed mail — without it, impersonation is far easier.",
      fix: `# Add a TXT record at _dmarc.yourdomain.com:\n"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com"   # start at none, then tighten`,
    });
  }

  // CAA
  findings.push(
    dns.caa
      ? {
          id: "caa",
          category: "dns",
          title: "CAA record present",
          status: "pass",
          points: 4,
          maxPoints: 4,
          severity: "info",
          detail: "CAA records restrict which certificate authorities may issue certificates for your domain.",
        }
      : {
          id: "caa",
          category: "dns",
          title: "No CAA record",
          status: "warn",
          points: 0,
          maxPoints: 4,
          severity: "low",
          detail: "No CAA record. Adding one limits which CAs can issue certificates for your domain, reducing mis-issuance risk.",
          fix: `# Add a CAA DNS record, e.g. to allow only Let's Encrypt:\nyourdomain.com. IN CAA 0 issue "letsencrypt.org"`,
        }
  );

  return findings;
}

// ---------- Cookies ----------

export function checkCookies(cookies: string[]): Finding | null {
  if (!cookies.length) return null;
  const insecure = cookies.filter(
    (c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c) || !/;\s*samesite/i.test(c)
  );
  if (insecure.length === 0) {
    return {
      id: "cookies",
      category: "cookies",
      title: "Cookies are hardened",
      status: "pass",
      points: 8,
      maxPoints: 8,
      severity: "medium",
      detail: "Every Set-Cookie includes Secure, HttpOnly, and SameSite.",
    };
  }
  return {
    id: "cookies",
    category: "cookies",
    title: `${insecure.length} cookie(s) missing security flags`,
    status: "warn",
    points: 2,
    maxPoints: 8,
    severity: "medium",
    detail:
      "One or more cookies lack Secure, HttpOnly, or SameSite. These flags stop cookies from leaking over HTTP, being read by scripts (XSS), or being sent in cross-site requests (CSRF).",
    fix: `Set-Cookie: session=…; Secure; HttpOnly; SameSite=Lax; Path=/`,
  };
}

// ---------- Information Disclosure ----------

export function checkServerBanner(headers: Headers): Finding {
  const server = H(headers, "server");
  const leaks = /\d+\.\d+/.test(server);
  if (server && leaks) {
    return {
      id: "server-banner",
      category: "disclosure",
      title: "Server version exposed",
      status: "warn",
      points: 0,
      maxPoints: 5,
      severity: "low",
      evidence: server,
      detail: `The Server header reveals "${server}". Advertising exact versions helps attackers match known exploits.`,
      fix: `# nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off`,
    };
  }
  return {
    id: "server-banner",
    category: "disclosure",
    title: "No server version leak",
    status: "pass",
    points: 5,
    maxPoints: 5,
    severity: "info",
    detail: server ? `Server header ("${server}") doesn't expose a precise version.` : "No Server version disclosure detected.",
  };
}

export function checkPoweredBy(headers: Headers): Finding {
  const p = H(headers, "x-powered-by");
  if (p) {
    return {
      id: "powered-by",
      category: "disclosure",
      title: "X-Powered-By exposes your stack",
      status: "warn",
      points: 0,
      maxPoints: 5,
      severity: "low",
      evidence: p,
      detail: `X-Powered-By reveals "${p}". Remove it so you don't hand attackers free reconnaissance.`,
      fix: `# Express\napp.disable('x-powered-by');\n\n# PHP (php.ini)\nexpose_php = Off\n\n# nginx reverse proxy\nproxy_hide_header X-Powered-By;`,
    };
  }
  return {
    id: "powered-by",
    category: "disclosure",
    title: "No X-Powered-By leak",
    status: "pass",
    points: 5,
    maxPoints: 5,
    severity: "info",
    detail: "The server doesn't advertise its framework via X-Powered-By.",
  };
}

export function checkSecurityTxt(found: boolean): Finding {
  return found
    ? {
        id: "security-txt",
        category: "disclosure",
        title: "security.txt published",
        status: "pass",
        points: 4,
        maxPoints: 4,
        severity: "info",
        detail: "A /.well-known/security.txt gives researchers a clear, standard way to report vulnerabilities to you (RFC 9116).",
      }
    : {
        id: "security-txt",
        category: "disclosure",
        title: "No security.txt",
        status: "warn",
        points: 0,
        maxPoints: 4,
        severity: "low",
        detail: "No /.well-known/security.txt. Publishing one gives security researchers a standard contact for responsible disclosure.",
        fix: `# Serve this at https://yourdomain.com/.well-known/security.txt\nContact: mailto:security@yourdomain.com\nExpires: 2027-01-01T00:00:00.000Z\nPreferred-Languages: en`,
      };
}

// ---------- Advanced Transport (TLS depth) ----------

export function checkForwardSecrecy(tls: TlsInfo | null): Finding {
  if (!tls || !tls.cipher) {
    return {
      id: "forward-secrecy",
      category: "transport",
      title: "Cipher suite not inspected",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "We couldn't read the negotiated cipher suite.",
    };
  }
  return tls.forwardSecrecy
    ? {
        id: "forward-secrecy",
        category: "transport",
        title: "Forward secrecy enabled",
        status: "pass",
        points: 5,
        maxPoints: 5,
        severity: "medium",
        evidence: tls.cipher,
        detail:
          "The connection uses an (EC)DHE key exchange, so past traffic stays private even if the server's key is later compromised.",
      }
    : {
        id: "forward-secrecy",
        category: "transport",
        title: "No forward secrecy",
        status: "fail",
        points: 0,
        maxPoints: 5,
        severity: "medium",
        evidence: tls.cipher,
        detail:
          "The negotiated cipher does not provide forward secrecy. If the private key is ever exposed, previously recorded traffic can be decrypted.",
        fix: `# nginx — prefer ECDHE suites (and enable TLS 1.3)\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\nssl_prefer_server_ciphers off;`,
      };
}

export function checkKeyStrength(tls: TlsInfo | null): Finding {
  if (!tls || !tls.keyType) {
    return {
      id: "key-strength",
      category: "transport",
      title: "Key strength not inspected",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "We couldn't determine the certificate's public-key type.",
    };
  }
  const weakRsa = tls.keyType === "RSA" && (tls.keyBits ?? 0) < 2048;
  return weakRsa
    ? {
        id: "key-strength",
        category: "transport",
        title: `Weak certificate key (RSA ${tls.keyBits})`,
        status: "fail",
        points: 0,
        maxPoints: 4,
        severity: "high",
        detail:
          "The certificate uses an RSA key shorter than 2048 bits, which is considered breakable. Reissue with a 2048-bit (or stronger) RSA or an ECDSA P-256 key.",
        fix: "Reissue the certificate with at least RSA-2048 or ECDSA P-256.",
      }
    : {
        id: "key-strength",
        category: "transport",
        title: `Strong certificate key (${tls.keyType}${tls.keyBits ? ` ${tls.keyBits}` : ""})`,
        status: "pass",
        points: 4,
        maxPoints: 4,
        severity: "info",
        detail:
          tls.keyType === "EC"
            ? "The certificate uses a modern elliptic-curve key — compact and strong."
            : "The certificate uses an RSA key of 2048 bits or more.",
      };
}

export function checkOcsp(tls: TlsInfo | null): Finding {
  if (!tls) {
    return {
      id: "ocsp",
      category: "transport",
      title: "OCSP stapling not inspected",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "We couldn't complete a TLS handshake to check OCSP stapling.",
    };
  }
  return tls.ocspStapled
    ? {
        id: "ocsp",
        category: "transport",
        title: "OCSP stapling enabled",
        status: "pass",
        points: 4,
        maxPoints: 4,
        severity: "low",
        detail:
          "The server staples a signed OCSP response, so browsers can verify the certificate isn't revoked without a slow, privacy-leaking call to the CA.",
      }
    : {
        id: "ocsp",
        category: "transport",
        title: "OCSP stapling not enabled",
        status: "warn",
        points: 0,
        maxPoints: 4,
        severity: "low",
        detail:
          "The server does not staple OCSP. Enabling it speeds up the handshake and improves privacy for revocation checks.",
        fix: `# nginx\nssl_stapling on;\nssl_stapling_verify on;\nresolver 1.1.1.1 8.8.8.8 valid=300s;`,
      };
}

// ---------- Advanced DNS & Email ----------

export function checkDnssec(dnssec: boolean): Finding {
  return dnssec
    ? {
        id: "dnssec",
        category: "dns",
        title: "DNSSEC enabled",
        status: "pass",
        points: 6,
        maxPoints: 6,
        severity: "medium",
        detail:
          "DNS responses are cryptographically signed (validated AD flag), protecting visitors from DNS spoofing and cache-poisoning.",
      }
    : {
        id: "dnssec",
        category: "dns",
        title: "DNSSEC not enabled",
        status: "warn",
        points: 0,
        maxPoints: 6,
        severity: "medium",
        detail:
          "Your DNS zone isn't signed with DNSSEC. Without it, attackers who can tamper with DNS can silently redirect your visitors.",
        fix: "Enable DNSSEC in your DNS provider / registrar (often a one-click toggle), then add the DS record at your registrar.",
      };
}

export function checkMtaSts(mtaSts: boolean, hasMx: boolean): Finding {
  if (!hasMx) {
    return {
      id: "mta-sts",
      category: "dns",
      title: "MTA-STS not applicable (no mail servers)",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "The domain publishes no MX records, so inbound-mail transport policies don't apply.",
    };
  }
  return mtaSts
    ? {
        id: "mta-sts",
        category: "dns",
        title: "MTA-STS enforced",
        status: "pass",
        points: 4,
        maxPoints: 4,
        severity: "medium",
        detail:
          "MTA-STS tells sending servers to require TLS for mail to your domain, blocking downgrade and interception attacks.",
      }
    : {
        id: "mta-sts",
        category: "dns",
        title: "No MTA-STS policy",
        status: "warn",
        points: 0,
        maxPoints: 4,
        severity: "medium",
        detail:
          "Without MTA-STS, mail to your domain can be delivered over unencrypted or downgraded connections.",
        fix: `# 1) TXT at _mta-sts.yourdomain.com:\n"v=STSv1; id=$(date +%s)"\n# 2) Serve https://mta-sts.yourdomain.com/.well-known/mta-sts.txt:\nversion: STSv1\nmode: enforce\nmx: mail.yourdomain.com\nmax_age: 604800`,
      };
}

export function checkTlsRpt(tlsRpt: boolean, hasMx: boolean): Finding {
  if (!hasMx) {
    return {
      id: "tls-rpt",
      category: "dns",
      title: "TLS-RPT not applicable (no mail servers)",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "The domain publishes no MX records.",
    };
  }
  return tlsRpt
    ? {
        id: "tls-rpt",
        category: "dns",
        title: "SMTP TLS Reporting enabled",
        status: "pass",
        points: 3,
        maxPoints: 3,
        severity: "low",
        detail: "TLS-RPT is published, so you receive reports when mail servers fail to negotiate TLS.",
      }
    : {
        id: "tls-rpt",
        category: "dns",
        title: "No SMTP TLS Reporting (TLS-RPT)",
        status: "warn",
        points: 0,
        maxPoints: 3,
        severity: "low",
        detail: "Publish TLS-RPT to get visibility into mail-delivery TLS failures against your domain.",
        fix: `# TXT at _smtp._tls.yourdomain.com:\n"v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain.com"`,
      };
}

export function checkDkim(dkim: boolean, selector: string | null, hasMx: boolean): Finding {
  if (dkim) {
    return {
      id: "dkim",
      category: "dns",
      title: `DKIM found (selector: ${selector})`,
      status: "pass",
      points: 6,
      maxPoints: 6,
      severity: "medium",
      detail:
        "A DKIM public key is published, so recipients can cryptographically verify your mail wasn't tampered with in transit.",
    };
  }
  return {
    id: "dkim",
    category: "dns",
    title: "No DKIM found for common selectors",
    status: "warn",
    points: 0,
    maxPoints: 0, // best-effort (custom selectors exist) — surfaced without penalising the score
    severity: hasMx ? "medium" : "low",
    detail:
      "We checked common DKIM selectors (default, google, selector1/2, k1, mail) and found none. You may use a custom selector — verify DKIM is signing your outbound mail.",
    fix: `# Publish your provider's DKIM public key as a TXT record at:\n<selector>._domainkey.yourdomain.com`,
  };
}

export function checkBimi(bimi: boolean): Finding {
  return bimi
    ? {
        id: "bimi",
        category: "dns",
        title: "BIMI logo published",
        status: "pass",
        points: 2,
        maxPoints: 2,
        severity: "info",
        detail:
          "A BIMI record is published, letting supporting inboxes show your verified brand logo next to authenticated mail.",
      }
    : {
        id: "bimi",
        category: "dns",
        title: "No BIMI record",
        status: "info",
        points: 0,
        maxPoints: 0,
        severity: "info",
        detail:
          "BIMI (optional) displays your brand logo in supporting inboxes once DMARC is enforced. A nice trust signal once your email auth is solid.",
      };
}

// ---------- Content Integrity ----------

export function checkMixedContent(mixed: MixedContent | null, isHttps: boolean): Finding {
  if (!isHttps) {
    return {
      id: "mixed-content",
      category: "content",
      title: "Mixed content not applicable (HTTP)",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "The page isn't served over HTTPS, so mixed-content rules don't apply yet.",
    };
  }
  if (!mixed) {
    return {
      id: "mixed-content",
      category: "content",
      title: "Page markup not analyzed",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "The response wasn't HTML we could analyze for mixed content.",
    };
  }
  if (mixed.count > 0) {
    return {
      id: "mixed-content",
      category: "content",
      title: `${mixed.count} active mixed-content resource(s)`,
      status: "fail",
      points: 0,
      maxPoints: 10,
      severity: "high",
      evidence: mixed.samples.slice(0, 3).join("  ·  "),
      detail:
        "The HTTPS page loads scripts, images, or frames over plain http://. Browsers may block them or downgrade the page's security, and attackers on the network can tamper with them.",
      fix: `# Upgrade every resource to https:// and add:\nContent-Security-Policy: upgrade-insecure-requests`,
    };
  }
  return {
    id: "mixed-content",
    category: "content",
    title: "No mixed content",
    status: "pass",
    points: 10,
    maxPoints: 10,
    severity: "medium",
    detail: "Every sub-resource on the page is loaded over HTTPS — no insecure scripts, images, or frames.",
  };
}

export function checkMethods(allow: string | null): Finding {
  if (!allow) {
    return {
      id: "http-methods",
      category: "disclosure",
      title: "HTTP methods not disclosed",
      status: "info",
      points: 0,
      maxPoints: 0,
      severity: "info",
      detail: "The server didn't advertise its allowed HTTP methods via an OPTIONS response.",
    };
  }
  const dangerous = ["TRACE", "TRACK", "PUT", "DELETE", "CONNECT"].filter((m) =>
    new RegExp(`\\b${m}\\b`, "i").test(allow)
  );
  if (dangerous.length) {
    return {
      id: "http-methods",
      category: "disclosure",
      title: `Risky HTTP methods enabled: ${dangerous.join(", ")}`,
      status: "warn",
      points: 0,
      maxPoints: 3,
      severity: "medium",
      evidence: allow,
      detail: `The server allows ${dangerous.join(", ")}. Methods like TRACE and PUT are rarely needed and can expose the app to cross-site tracing or unauthorized writes.`,
      fix: `# Restrict to what your app needs (nginx):\nif ($request_method !~ ^(GET|POST|HEAD|OPTIONS)$) { return 405; }`,
    };
  }
  return {
    id: "http-methods",
    category: "disclosure",
    title: "Only safe HTTP methods allowed",
    status: "pass",
    points: 3,
    maxPoints: 3,
    severity: "info",
    evidence: allow,
    detail: "The server advertises only standard, safe HTTP methods.",
  };
}
