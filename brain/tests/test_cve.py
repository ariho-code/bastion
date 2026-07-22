"""Tests for heuristic CVE correlation."""

from __future__ import annotations

from app.analyzer import analyze
from app.cve import correlate
from app.models import Finding, ScanResult


def _f(evidence: str) -> Finding:
    return Finding(id="x", category="surface", title="Open ports", status="info",
                   severity="info", evidence=evidence)


def test_detects_old_openssh() -> None:
    matches = correlate([_f("22/SSH (SSH-2.0-OpenSSH_6.6.1p1 Ubuntu)")])
    assert any(m.product == "openssh" for m in matches)
    assert any(m.severity == "critical" for m in matches)


def test_current_version_not_flagged() -> None:
    matches = correlate([_f("Server: nginx/1.25.3")])
    assert matches == []


def test_detects_old_jquery() -> None:
    matches = correlate([_f("jquery-3.4.1.min.js")])
    assert any(m.product == "jquery" for m in matches)


def test_analyze_surfaces_cve_and_raises_risk() -> None:
    findings = [
        Finding(id="p", category="surface", title="Open ports", status="info",
                severity="info", evidence="22/SSH (SSH-2.0-OpenSSH_6.6.1p1)"),
    ]
    scan = ScanResult(target="host", host="host", grade="C", score=70, findings=findings)
    result = analyze(scan)
    assert len(result.cve_matches) >= 1
    assert result.risk_index >= 50  # a critical CVE must not read as low risk
    assert any(r.category == "software" for r in result.remediation)
