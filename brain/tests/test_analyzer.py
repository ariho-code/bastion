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


# --- scam / phishing verdict -------------------------------------------------

def _phishing_findings(verdict: str, severity: str, *, brand: bool = False, seed: bool = False) -> list[Finding]:
    out = [
        Finding(
            id="phishing.verdict", module="phishing", category="scam",
            title=f"Scam verdict: {verdict}", status="fail" if severity != "info" else "pass",
            severity=severity,
            detail=f"{verdict} — this site shows signs of a scam." if severity != "info" else "SAFE — no scam indicators.",
        ),
    ]
    if brand:
        out.append(Finding(
            id="phishing.impersonation", module="phishing", category="scam",
            title="Brand impersonation", status="fail", severity="critical", maxPoints=45,
            detail="This domain is impersonating PayPal. Legitimate PayPal services never use look-alike domains.",
            fix="Do not enter credentials.",
        ))
    if seed:
        out.append(Finding(
            id="phishing.harvesting", module="phishing", category="scam",
            title="Credential & wallet harvesting", status="fail", severity="critical", maxPoints=35,
            detail="This page asks for a wallet recovery/seed phrase. No legitimate wallet ever asks for this.",
        ))
    return out


def test_scam_verdict_absent_when_module_did_not_run() -> None:
    scan = _scan([Finding(id="a", category="headers", title="CSP", status="pass", severity="info")])
    assert analyze(scan).scam is None


def test_scam_verdict_safe() -> None:
    scan = _scan(_phishing_findings("SAFE", "info"), grade="A", score=100)
    scam = analyze(scan).scam
    assert scam is not None
    assert scam.verdict == "SAFE"
    assert scam.level == 0
    assert scam.is_scam is False


def test_scam_verdict_dangerous_leads_narrative() -> None:
    scan = _scan(_phishing_findings("DANGEROUS", "critical", brand=True, seed=True))
    result = analyze(scan)
    scam = result.scam
    assert scam is not None
    assert scam.verdict == "DANGEROUS"
    assert scam.level == 3
    assert scam.is_scam is True
    assert scam.brand == "PayPal"
    assert any("seed phrase" in r for r in scam.reasons)
    # The scam verdict must lead the executive narrative.
    assert result.headline == scam.headline
    assert scam.advice in result.summary


def test_scam_verdict_suspicious_from_label() -> None:
    scan = _scan(_phishing_findings("SUSPICIOUS", "high", brand=True))
    scam = analyze(scan).scam
    assert scam is not None and scam.verdict == "SUSPICIOUS" and scam.level == 2 and scam.is_scam
