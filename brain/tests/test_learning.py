"""Tests for the continuous learning store and weight recalibration."""

from __future__ import annotations

from pathlib import Path

from app.ai.learning import LearningStore
from app.analyzer import analyze
from app.models import Finding, ScanResult


def test_feedback_adjusts_weights(tmp_path: Path) -> None:
    store = LearningStore(tmp_path)
    store.record_feedback(finding_id="active.xss", label="false_positive", target="a.com")
    store.record_feedback(finding_id="active.xss", label="false_positive", target="b.com")
    store.record_feedback(finding_id="active.sqli", label="true_positive", target="c.com")
    w = store.finding_weights()
    assert w["active.xss"] < 1.0
    assert w["active.sqli"] > 1.0


def test_learning_weights_dampen_risk(tmp_path: Path) -> None:
    store = LearningStore(tmp_path)
    store.record_feedback(finding_id="noise.finding", label="false_positive")
    findings = [
        Finding(
            id="noise.finding",
            category="headers",
            title="Noisy",
            status="fail",
            severity="high",
            points=0,
            maxPoints=10,
        )
    ]
    scan = ScanResult(target="x.com", host="x.com", grade="C", score=70, findings=findings)
    base = analyze(scan)
    damped = analyze(scan, learning_weights=store.finding_weights())
    assert damped.risk_index <= base.risk_index


def test_record_and_list_scans(tmp_path: Path) -> None:
    store = LearningStore(tmp_path)
    sid = store.record_scan(
        target="bank.example",
        profile="active",
        vertical="banking",
        grade="B",
        score=85,
        risk_index=22,
        risk_level="Low",
        findings=[{"id": "a", "status": "pass"}],
        verified=True,
        tenant="acme",
    )
    assert sid
    rows = store.list_scans(tenant="acme", limit=10)
    assert len(rows) == 1
    assert rows[0]["vertical"] == "banking"
