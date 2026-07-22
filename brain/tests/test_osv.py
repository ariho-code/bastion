"""Tests for the live OSV.dev enrichment layer.

No network is used: the HTTP-bound `_query_one` is monkeypatched, and the pure
parsing/merging logic is exercised directly. Async functions are driven with
asyncio.run so no pytest-asyncio dependency is needed.
"""

from __future__ import annotations

import asyncio

from app import cve, osv
from app.config import config
from app.models import CVEMatch, Finding

# A representative OSV /v1/query "vulns" record (GHSA advisory for jQuery).
JQUERY_VULN = {
    "id": "GHSA-gxr4-xjj5-5px2",
    "summary": "Cross-site scripting (XSS) via jQuery.htmlPrefilter",
    "aliases": ["CVE-2020-11022"],
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "jquery"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}],
        }
    ],
}


def test_parse_vuln_maps_fields() -> None:
    m = osv.parse_vuln(JQUERY_VULN, "jquery", "3.4.1", "npm", "jquery")
    assert m is not None
    assert m.product == "jquery" and m.version == "3.4.1"
    assert m.severity == "medium"          # MODERATE -> medium
    assert m.cves == ["CVE-2020-11022"]     # prefers the CVE alias
    assert m.fixed_in == "3.5.0"
    assert m.source == "osv"
    assert m.url == "https://osv.dev/vulnerability/GHSA-gxr4-xjj5-5px2"


def test_parse_vuln_falls_back_to_id() -> None:
    v = {"id": "GHSA-zzzz", "summary": "x", "database_specific": {"severity": "HIGH"}}
    m = osv.parse_vuln(v, "vue", "2.0.0", "npm", "vue")
    assert m is not None
    assert m.cves == ["GHSA-zzzz"]
    assert m.severity == "high"


def test_severity_from_cvss_number() -> None:
    v = {"id": "X", "summary": "x", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert osv._severity_of(v) == "critical"


def test_enrich_maps_products_and_sorts(monkeypatch) -> None:
    async def fake_query(client, product, version):  # noqa: ANN001
        if product == "jquery":
            return [CVEMatch(product="jquery", version=version, fixed_in="3.5.0",
                             severity="medium", cves=["CVE-2020-11022"], summary="xss", source="osv")]
        if product == "lodash":
            return [CVEMatch(product="lodash", version=version, fixed_in="4.17.21",
                             severity="critical", cves=["CVE-2021-23337"], summary="cmd inj", source="osv")]
        return []

    monkeypatch.setattr(osv, "_query_one", fake_query)
    monkeypatch.setattr(config, "osv_enabled", True)
    out = asyncio.run(osv.enrich({"jquery": "3.4.1", "lodash": "4.17.11", "nginx": "1.18.0"}))
    # nginx has no OSV ecosystem mapping and is skipped; results are severity-sorted.
    assert [m.product for m in out] == ["lodash", "jquery"]


def test_enrich_disabled_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(config, "osv_enabled", False)
    out = asyncio.run(osv.enrich({"jquery": "3.4.1"}))
    assert out == []


def test_enrich_is_graceful_on_error(monkeypatch) -> None:
    async def boom(client, product, version):  # noqa: ANN001
        raise RuntimeError("network down")

    monkeypatch.setattr(osv, "_query_one", boom)
    monkeypatch.setattr(config, "osv_enabled", True)
    out = asyncio.run(osv.enrich({"jquery": "3.4.1"}))
    assert out == []  # a feed outage never propagates


def test_correlate_merges_live_and_dedupes() -> None:
    findings = [Finding(id="lib", category="surface", title="Libraries",
                        status="info", severity="info", evidence="jQuery 3.4.1")]
    # Live feed returns the same CVE the curated DB already knows, plus a new one.
    live = [
        CVEMatch(product="jquery", version="3.4.1", fixed_in="3.5.0", severity="medium",
                 cves=["CVE-2020-11022"], summary="dup", source="osv"),
        CVEMatch(product="jquery", version="3.4.1", fixed_in="3.5.0", severity="medium",
                 cves=["CVE-2019-11358"], summary="prototype pollution", source="osv"),
    ]
    merged = cve.correlate(findings, extra=live)
    all_cves = {c for m in merged for c in m.cves}
    # The overlapping CVE appears once; the genuinely new advisory is kept.
    assert "CVE-2019-11358" in all_cves
    assert sum(1 for m in merged if "CVE-2020-11022" in m.cves) == 1
