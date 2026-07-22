"""End-user AI payload must never leak developer internals."""

from __future__ import annotations

from app.ai.insights import _executive_offline, _offline_chat_reply, public_insights
from app.models import RiskAnalysis


def _analysis() -> RiskAnalysis:
    return RiskAnalysis(
        target="apple.com",
        grade="B",
        score=82,
        risk_index=55,
        risk_level="High",
        headline="apple.com scores B with high overall risk.",
        summary=["x"],
        strengths=[],
        critical_count=0,
        high_count=2,
        medium_count=3,
        low_count=1,
        category_risk=[],
        cve_matches=[],
        remediation=[],
    )


def test_public_insights_hides_stack() -> None:
    raw = {
        "summary": "Site looks fine.",
        "top_priorities": [{"title": "Fix cookies", "why": "Session theft", "effort": "Quick"}],
        "vertical_advice": "General advice",
        "false_positive_risks": [],
        "confidence": 0.5,
        "provider": "offline",
        "model": "rules+rag+ml",
        "source": "offline+rag",
        "learning_lessons_used": 6,
        "rag_hits": 6,
        "rag_citations": ["Active DAST safety: Bastionscan only runs..."],
    }
    pub = public_insights(raw)
    assert pub is not None
    assert pub["provider"] == "Bastionscan AI"
    assert "offline" not in pub.get("model", "").lower()
    assert pub.get("rag_citations") == []
    assert pub.get("rag_hits") == 0
    assert "rules" not in str(pub).lower()


def test_executive_offline_no_kb_dump() -> None:
    a = _analysis()
    raw = _executive_offline(
        a,
        "general",
        [{"title": "Cookies marked Secure", "severity": "high", "detail": "x"}],
        [{"kind": "knowledge", "text": "Active DAST safety: Bastionscan only runs intrusive probes"}],
    )
    blob = raw["summary"] + raw.get("vertical_advice", "")
    assert "Active DAST" not in blob
    assert "DEEPSEEK" not in blob
    assert "RAG" not in blob.upper() or "RAG" not in blob


def test_offline_chat_greeting() -> None:
    # chat_with_rag greeting path is tested indirectly via reply helper
    r = _offline_chat_reply(
        "what should I fix first?",
        "apple.com",
        {"grade": "B", "risk_level": "High", "headline": "apple.com scores B"},
        [],
    )
    assert "platform memory" not in r.lower()
    assert "api key" not in r.lower()
    assert "apple.com" in r.lower() or "fix" in r.lower() or "first" in r.lower()
