"""Unit tests for the risk analyzer — pure, deterministic, no network."""

from __future__ import annotations

from app.analyzer import analyze
from app.models import Finding, ScanResult


def _scan(findings: list[Finding], grade: str = "C", score: int = 70) -> ScanResult:
    return ScanResult(target="example.com", host="example.com", grade=grade, score=score, findings=findings)


def test_clean_scan_is_minimal_risk() -> None:
    scan = _scan(
        [
            Finding(id="a", category="headers", title="CSP", status="pass", severity="info", points=15, maxPoints=15),
            Finding(id="b", category="transport", title="HSTS", status="pass", severity="info", points=12, maxPoints=12),
        ],
        grade="A",
        score=100,
    )
    result = analyze(scan)
    assert result.risk_index == 0
    assert result.risk_level == "Minimal"
    assert result.critical_count == 0
    assert "CSP" in result.strengths


def test_critical_finding_drives_high_risk() -> None:
    scan = _scan(
        [
            Finding(
                id="x", category="disclosure", title="Exposed .env", status="fail",
                severity="critical", points=0, maxPoints=20, fix="Remove it",
            ),
        ]
    )
    result = analyze(scan)
    assert result.critical_count == 1
    assert result.risk_index >= 50
    assert result.risk_level in ("High", "Critical")
    assert result.remediation[0].priority == "P1"
    assert result.remediation[0].points_lost == 20


def test_remediation_is_priority_ordered() -> None:
    scan = _scan(
        [
            Finding(id="low", category="headers", title="Referrer", status="warn", severity="low", points=0, maxPoints=6),
            Finding(id="crit", category="surface", title="Open DB", status="fail", severity="critical", points=0, maxPoints=20),
            Finding(id="med", category="cookies", title="HttpOnly", status="warn", severity="medium", points=0, maxPoints=10),
        ]
    )
    result = analyze(scan)
    priorities = [item.priority for item in result.remediation]
    # P1 (critical) must come before higher-numbered priorities.
    assert priorities[0] == "P1"
    assert priorities == sorted(priorities)


def test_warn_dampens_severity_priority() -> None:
    scan = _scan(
        [Finding(id="w", category="dns", title="CAA", status="warn", severity="low", points=0, maxPoints=6)]
    )
    result = analyze(scan)
    # low + warn -> P4 (min capped)
    assert result.remediation[0].priority == "P4"
    assert result.remediation[0].effort == "Quick"


def test_category_risk_sorted_desc() -> None:
    scan = _scan(
        [
            Finding(id="c1", category="surface", title="Port", status="fail", severity="critical", points=0, maxPoints=20),
            Finding(id="c2", category="headers", title="CSP", status="fail", severity="medium", points=0, maxPoints=15),
        ]
    )
    result = analyze(scan)
    risks = [c.risk for c in result.category_risk]
    assert risks == sorted(risks, reverse=True)
    assert result.category_risk[0].category == "surface"
