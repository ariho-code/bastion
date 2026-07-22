import type { Metadata } from "next";
import { brand, SITE_URL } from "@/lib/brand";

export const metadata: Metadata = {
  title: "API Documentation",
  description: `Scan any website's security posture programmatically with the ${brand.name} REST API. A–F grading across 28 checks — TLS, headers, DNSSEC, email auth and more — as clean JSON.`,
  alternates: { canonical: "/docs" },
};

const curl = `curl -s "${SITE_URL}/api/v1/scan?url=example.com" \\
  -H "Authorization: Bearer YOUR_API_KEY"`;

const js = `const res = await fetch("${SITE_URL}/api/v1/scan", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer YOUR_API_KEY",
  },
  body: JSON.stringify({ url: "example.com" }),
});
const { ok, data } = await res.json();
console.log(data.grade, data.score); // "A", 95`;

const py = `import requests

r = requests.post(
    "${SITE_URL}/api/v1/scan",
    headers={"Authorization": "Bearer YOUR_API_KEY"},
    json={"url": "example.com"},
)
data = r.json()["data"]
print(data["grade"], data["score"])`;

const sample = `{
  "ok": true,
  "tier": "pro",
  "data": {
    "host": "example.com",
    "grade": "A",
    "score": 95,
    "passed": 22, "warnings": 4, "failed": 2,
    "categories": [
      { "category": "transport", "label": "Transport & TLS", "score": 100 }
    ],
    "findings": [
      {
        "id": "hsts", "category": "transport",
        "title": "HSTS enabled", "status": "pass",
        "severity": "high", "points": 15, "maxPoints": 15,
        "detail": "…", "fix": "…"
      }
    ],
    "meta": { "dnssec": true, "tls": { "protocol": "TLSv1.3" } }
  }
}`;

function Method({ m }: { m: string }) {
  return <span className={`docs-method docs-method-${m.toLowerCase()}`}>{m}</span>;
}

export default function DocsPage() {
  return (
    <main className="legal docs">
      <span className="eyebrow">Developers</span>
      <h1>{brand.name} API</h1>
      <p className="docs-lead">
        Grade any website&apos;s live security posture programmatically — <strong>28 checks</strong>{" "}
        across TLS, response headers, DNSSEC, email authentication, cookies and content integrity —
        returned as clean, structured JSON. Perfect for CI/CD gates, dashboards, and monitoring.
      </p>

      <h2>Base URL</h2>
      <pre className="code">{`${SITE_URL}/api/v1`}</pre>

      <h2>Authentication</h2>
      <p>
        Send your key as a bearer token (or an <code>x-api-key</code> header). Anonymous requests are
        allowed at a low rate so you can try it; keyed requests get much higher limits.
      </p>
      <pre className="code">{`Authorization: Bearer YOUR_API_KEY`}</pre>
      <p>
        Need a key? <a href="/#pricing">Grab one with a Pro or Agency plan</a> — or email{" "}
        <a href={`mailto:${brand.contactEmail}`}>{brand.contactEmail}</a>.
      </p>

      <h2>Scan a site</h2>
      <p className="docs-endpoint">
        <Method m="GET" /> <Method m="POST" /> <code>/api/v1/scan</code>
      </p>
      <table className="docs-table">
        <thead>
          <tr>
            <th>Parameter</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <code>url</code>
            </td>
            <td>string</td>
            <td>
              The site to scan. Query param for <code>GET</code>, JSON body field for{" "}
              <code>POST</code>. Scheme optional (defaults to https).
            </td>
          </tr>
        </tbody>
      </table>

      <h3>cURL</h3>
      <pre className="code">{curl}</pre>
      <h3>JavaScript</h3>
      <pre className="code">{js}</pre>
      <h3>Python</h3>
      <pre className="code">{py}</pre>

      <h2>Response</h2>
      <p>
        A <code>200</code> returns <code>{`{ ok: true, data }`}</code> where <code>data</code> is the
        full scan result. Every request includes <code>X-RateLimit-Limit</code> and{" "}
        <code>X-RateLimit-Remaining</code> headers.
      </p>
      <pre className="code">{sample}</pre>

      <h2>Rate limits</h2>
      <table className="docs-table">
        <thead>
          <tr>
            <th>Tier</th>
            <th>Requests / day</th>
            <th>Auth</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Anonymous</td>
            <td>30</td>
            <td>None (per IP)</td>
          </tr>
          <tr>
            <td>Pro</td>
            <td>5,000</td>
            <td>API key</td>
          </tr>
          <tr>
            <td>Agency</td>
            <td>100,000</td>
            <td>API key</td>
          </tr>
        </tbody>
      </table>

      <h2>Errors</h2>
      <p>
        Errors return <code>{`{ ok: false, error }`}</code> with a standard status code:{" "}
        <code>400</code> bad request, <code>401</code> missing key, <code>429</code> rate limited,{" "}
        <code>502</code> unreachable site.
      </p>

      <div className="docs-cta">
        <div>
          <strong>Build security into your pipeline.</strong>
          <span>Fail your CI when a site drops below an A. Get an API key in minutes.</span>
        </div>
        <a href="/#pricing" className="final-btn">
          Get an API key
        </a>
      </div>
    </main>
  );
}
