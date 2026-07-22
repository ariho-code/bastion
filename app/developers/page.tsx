import type { Metadata } from "next";
import CodeTabs from "@/components/CodeTabs";
import { brand, SITE_URL } from "@/lib/brand";

export const metadata: Metadata = {
  title: `API & Developers — ${brand.name}`,
  description:
    "Automate website security scans with the Bastionscan API. Tiered API keys, standard rate-limit headers, an OpenAPI spec, and code samples in cURL, JavaScript, Python and Go.",
  alternates: { canonical: `${SITE_URL}/developers` },
};

const ENGINE = "https://bastionscan-engine.onrender.com";

const SCAN_SAMPLES = [
  {
    label: "cURL",
    code: `curl -X POST ${ENGINE}/v1/scan \\
  -H "Authorization: Bearer $BASTION_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target":"example.com","profile":"deep"}'`,
  },
  {
    label: "JavaScript",
    code: `const res = await fetch("${ENGINE}/v1/scan", {
  method: "POST",
  headers: {
    Authorization: \`Bearer \${process.env.BASTION_API_KEY}\`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ target: "example.com", profile: "deep" }),
});

const report = await res.json();
console.log(report.grade, report.score); // "B" 86`,
  },
  {
    label: "Python",
    code: `import os, httpx

r = httpx.post(
    "${ENGINE}/v1/scan",
    headers={"Authorization": f"Bearer {os.environ['BASTION_API_KEY']}"},
    json={"target": "example.com", "profile": "deep"},
    timeout=60,
)
report = r.json()
print(report["grade"], report["score"])  # B 86`,
  },
  {
    label: "Go",
    code: `package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	body, _ := json.Marshal(map[string]any{
		"target": "example.com", "profile": "deep",
	})
	req, _ := http.NewRequest("POST", "${ENGINE}/v1/scan", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("BASTION_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	resp, _ := http.DefaultClient.Do(req)
	defer resp.Body.Close()

	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	fmt.Println(out["grade"], out["score"])
}`,
  },
];

const RESPONSE_SAMPLE = `{
  "host": "example.com",
  "grade": "B",
  "score": 86,
  "profile": "deep",
  "categories": [
    { "category": "transport", "label": "Transport & TLS", "score": 87 },
    { "category": "headers",   "label": "Response Headers", "score": 73 }
  ],
  "findings": [
    {
      "id": "tls.ciphers",
      "category": "transport",
      "title": "Strong cipher suites only",
      "status": "fail",
      "severity": "high",
      "detail": "Weak cipher suite(s) accepted (CBC/3DES/RC4/SHA-1).",
      "fix": "Disable CBC-mode, 3DES, RC4 and SHA-1 cipher suites."
    }
  ],
  "passed": 23, "warnings": 5, "failed": 1,
  "durationMs": 3820, "engineVersion": "0.1.0"
}`;

const TIERS = [
  { tier: "anonymous", limit: "60 / min", note: "No key. Public endpoints only." },
  { tier: "free", limit: "120 / min", note: "Free API key." },
  { tier: "pro", limit: "600 / min", note: "Higher throughput + priority." },
  { tier: "agency", limit: "3000 / min", note: "Bulk / multi-tenant." },
];

const ENDPOINTS = [
  { method: "POST", path: "/v1/scan", auth: true, desc: "Run a scan; returns a graded report." },
  { method: "GET", path: "/v1/scan?target=", auth: true, desc: "Same, via query params." },
  { method: "GET", path: "/v1/modules", auth: false, desc: "List registered scanner modules." },
  { method: "GET", path: "/health", auth: false, desc: "Liveness + capability snapshot." },
  { method: "GET", path: "/metrics", auth: false, desc: "Prometheus metrics." },
  { method: "GET", path: "/openapi.yaml", auth: false, desc: "Machine-readable OpenAPI 3.1 spec." },
];

const ERRORS = [
  { code: "400", when: "Invalid target (bad URL, embedded credentials, non-web port)." },
  { code: "401", when: "Missing/invalid API key when keys are required." },
  { code: "403", when: "Target blocked (private, internal or non-public address)." },
  { code: "429", when: "Rate limit or per-target cooldown hit — see Retry-After." },
];

export default function DevelopersPage() {
  return (
    <main className="dev">
      <header className="dev-head">
        <span className="dev-eyebrow">Developers</span>
        <h1 className="dev-title">
          The <span className="grad">Bastionscan API</span>
        </h1>
        <p className="dev-lede">
          Automate security scans in CI/CD, fail builds below an A, or embed live grades in your own
          dashboards. A fast, concurrent engine behind a clean REST API — tiered keys, standard
          rate-limit headers, and an OpenAPI spec.
        </p>
        <div className="dev-baseurl">
          <span className="dev-baseurl-label">Base URL</span>
          <code>{ENGINE}</code>
        </div>
      </header>

      {/* Quick start */}
      <section className="dev-section">
        <h2>Quick start</h2>
        <p>Send a target, get a graded report. Pass your API key as a bearer token.</p>
        <CodeTabs samples={SCAN_SAMPLES} />
      </section>

      {/* Authentication */}
      <section className="dev-section">
        <h2>Authentication</h2>
        <p>
          Provide your key as <code>Authorization: Bearer &lt;key&gt;</code> or{" "}
          <code>X-API-Key: &lt;key&gt;</code>. Keys are matched in constant time and map to a tier.
          Public endpoints (<code>/health</code>, <code>/v1/modules</code>) need no key.
        </p>
        <div className="dev-table-wrap">
          <table className="dev-table">
            <thead>
              <tr>
                <th>Tier</th>
                <th>Rate limit</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {TIERS.map((t) => (
                <tr key={t.tier}>
                  <td>
                    <span className="dev-pill">{t.tier}</span>
                  </td>
                  <td className="mono">{t.limit}</td>
                  <td>{t.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Rate limits */}
      <section className="dev-section">
        <h2>Rate limits</h2>
        <p>Every response carries standard headers so you can back off gracefully:</p>
        <ul className="dev-list">
          <li>
            <code>X-RateLimit-Limit</code> — your tier&apos;s per-minute cap
          </li>
          <li>
            <code>X-RateLimit-Remaining</code> — requests left in the window
          </li>
          <li>
            <code>X-RateLimit-Reset</code> — seconds until the window refills
          </li>
          <li>
            <code>Retry-After</code> — sent on <code>429</code>, in seconds
          </li>
        </ul>
        <p className="dev-note">
          The same host is also protected by a short per-target cooldown, so the engine can&apos;t be
          used to flood a single site.
        </p>
      </section>

      {/* Endpoints */}
      <section className="dev-section">
        <h2>Endpoints</h2>
        <div className="dev-table-wrap">
          <table className="dev-table">
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Auth</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {ENDPOINTS.map((e) => (
                <tr key={e.path}>
                  <td>
                    <span className={`dev-method m-${e.method.toLowerCase()}`}>{e.method}</span>
                  </td>
                  <td className="mono">{e.path}</td>
                  <td>{e.auth ? "Key" : "—"}</td>
                  <td>{e.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <h3 className="dev-h3">Scan request</h3>
        <ul className="dev-list">
          <li>
            <code>target</code> <span className="req">required</span> — URL or hostname
          </li>
          <li>
            <code>profile</code> — <code>standard</code> (default), <code>deep</code>,{" "}
            <code>passive</code>, or <code>active</code> (verified targets only)
          </li>
        </ul>
      </section>

      {/* Response */}
      <section className="dev-section">
        <h2>Response</h2>
        <p>
          A graded report: an overall <code>A–F</code> grade and score, per-category scores, and
          detailed findings — each with severity, evidence and a copy-paste fix.
        </p>
        <CodeTabs samples={[{ label: "200 OK", code: RESPONSE_SAMPLE }]} />
      </section>

      {/* Errors */}
      <section className="dev-section">
        <h2>Errors</h2>
        <div className="dev-table-wrap">
          <table className="dev-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {ERRORS.map((e) => (
                <tr key={e.code}>
                  <td>
                    <span className="dev-code-badge">{e.code}</span>
                  </td>
                  <td>{e.when}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Resources */}
      <section className="dev-section">
        <h2>Resources</h2>
        <div className="dev-cards">
          <a className="dev-card" href={`${ENGINE}/openapi.yaml`} target="_blank" rel="noreferrer">
            <h3>OpenAPI 3.1 spec</h3>
            <p>Import into Postman, Insomnia, or generate a client.</p>
          </a>
          <a className="dev-card" href="https://bastionscan-brain.onrender.com/docs" target="_blank" rel="noreferrer">
            <h3>Interactive docs</h3>
            <p>Try the risk-analysis API live (Swagger UI).</p>
          </a>
          <a className="dev-card" href="https://github.com/ariho-code/bastion" target="_blank" rel="noreferrer">
            <h3>Source on GitHub</h3>
            <p>The engine, brain and this site — all open.</p>
          </a>
        </div>
      </section>
    </main>
  );
}
