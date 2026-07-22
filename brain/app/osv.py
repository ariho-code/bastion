"""Live vulnerability enrichment via the OSV.dev API.

The curated ``VULN_DB`` in :mod:`app.cve` is fast, deterministic, and offline —
but finite. This module augments it with real, continuously-updated advisories
from OSV.dev (https://osv.dev) for the components we can confidently map to an
OSV ecosystem (JavaScript libraries loaded from CDNs, chiefly).

Design principles:

* **Best-effort.** Every network path is wrapped so a timeout, outage, or
  malformed response yields an empty result — never an exception. A scan must
  never fail because the live feed is unavailable.
* **Precise.** OSV's ``/v1/query`` filters by version server-side, so we only
  receive advisories that actually affect the detected version.
* **Cheap.** Results are cached in-process with a TTL, and only mappable
  products trigger a request.
"""

from __future__ import annotations

import asyncio
import time

import httpx

from .config import config
from .models import CVEMatch

# Detected product -> (OSV ecosystem, package name). Only products OSV indexes
# reliably by package+version live here; everything else stays with the curated
# database. jQuery/Bootstrap/etc. are npm packages even when loaded from a CDN.
PRODUCT_ECOSYSTEM: dict[str, tuple[str, str]] = {
    "jquery": ("npm", "jquery"),
    "bootstrap": ("npm", "bootstrap"),
    "lodash": ("npm", "lodash"),
    "moment": ("npm", "moment"),
    "axios": ("npm", "axios"),
    "handlebars": ("npm", "handlebars"),
    "angular": ("npm", "angular"),  # AngularJS 1.x (the CDN-loaded, CVE-heavy line)
    "vue": ("npm", "vue"),
    "react": ("npm", "react"),
}

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Per-(ecosystem, name, version) cache: key -> (expires_at, matches).
_cache: dict[tuple[str, str, str], tuple[float, list[CVEMatch]]] = {}

MAX_PER_PRODUCT = 6


def _severity_of(vuln: dict) -> str:
    """Best-effort severity extraction from an OSV vuln record."""
    db = vuln.get("database_specific") or {}
    label = str(db.get("severity", "")).upper()
    if label in _SEVERITY_MAP:
        return _SEVERITY_MAP[label]
    # Fall back to a CVSS base score if a vector/score is present.
    for sev in vuln.get("severity") or []:
        score = str(sev.get("score", ""))
        num = _cvss_base(score)
        if num is not None:
            if num >= 9.0:
                return "critical"
            if num >= 7.0:
                return "high"
            if num >= 4.0:
                return "medium"
            return "low"
    return "medium"


def _cvss_base(score: str) -> float | None:
    """Return a numeric base score if `score` is already numeric (some OSV
    records store the number rather than a vector); otherwise None."""
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def _fixed_version(vuln: dict, ecosystem: str, name: str) -> str:
    """Pull the first 'fixed' version from the matching affected range."""
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") and pkg["name"].lower() != name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def _cve_ids(vuln: dict) -> list[str]:
    """Prefer CVE aliases; fall back to the OSV/GHSA id."""
    aliases = [a for a in (vuln.get("aliases") or []) if str(a).upper().startswith("CVE-")]
    if aliases:
        return aliases
    vid = vuln.get("id")
    return [vid] if vid else []


def parse_vuln(vuln: dict, product: str, version: str, ecosystem: str, name: str) -> CVEMatch | None:
    """Convert one OSV vuln record into a CVEMatch. Returns None if unusable."""
    ids = _cve_ids(vuln)
    if not ids:
        return None
    summary = (vuln.get("summary") or vuln.get("details") or "Known vulnerability.").strip()
    if len(summary) > 240:
        summary = summary[:237] + "…"
    fixed = _fixed_version(vuln, ecosystem, name)
    vid = vuln.get("id", "")
    return CVEMatch(
        product=product,
        version=version,
        fixed_in=fixed or "a patched release",
        severity=_severity_of(vuln),  # type: ignore[arg-type]
        cves=ids,
        summary=summary,
        source="osv",
        url=f"https://osv.dev/vulnerability/{vid}" if vid else None,
    )


async def _query_one(client: httpx.AsyncClient, product: str, version: str) -> list[CVEMatch]:
    """Query OSV for a single detected component. Never raises."""
    ecosystem, name = PRODUCT_ECOSYSTEM[product]
    key = (ecosystem, name, version)
    cached = _cache.get(key)
    now = time.monotonic()
    if cached and cached[0] > now:
        return cached[1]

    matches: list[CVEMatch] = []
    try:
        resp = await client.post(
            f"{config.osv_url}/v1/query",
            json={"version": version, "package": {"ecosystem": ecosystem, "name": name}},
        )
        if resp.status_code == 200:
            vulns = resp.json().get("vulns") or []
            for v in vulns:
                m = parse_vuln(v, product, version, ecosystem, name)
                if m:
                    matches.append(m)
            matches.sort(key=lambda m: _SEVERITY_ORDER.get(m.severity, 4))
            matches = matches[:MAX_PER_PRODUCT]
    except (httpx.HTTPError, ValueError, KeyError):
        matches = []  # best-effort: fall back to whatever the curated DB found

    _cache[key] = (now + config.osv_cache_ttl, matches)
    return matches


async def enrich(detected: dict[str, str]) -> list[CVEMatch]:
    """Return live OSV advisories for the mappable detected components.

    `detected` is {product: version} as produced by :func:`app.cve.detect`.
    Concurrent, timeout-bounded, and exception-safe: on any failure it returns
    whatever it managed to gather (possibly nothing).
    """
    if not config.osv_enabled:
        return []
    targets = [(p, v) for p, v in detected.items() if p in PRODUCT_ECOSYSTEM and v]
    if not targets:
        return []

    try:
        async with httpx.AsyncClient(timeout=config.osv_timeout) as client:
            results = await asyncio.gather(
                *(_query_one(client, p, v) for p, v in targets),
                return_exceptions=True,
            )
    except Exception:  # noqa: BLE001 - enrichment must never break a scan
        return []

    out: list[CVEMatch] = []
    for r in results:
        if isinstance(r, list):
            out.extend(r)
    out.sort(key=lambda m: _SEVERITY_ORDER.get(m.severity, 4))
    return out
