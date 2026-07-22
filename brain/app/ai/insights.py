"""AI enrichment: executive insight + learning-aware guidance from scans."""

from __future__ import annotations

from typing import Any

from ..models import RiskAnalysis, ScanResult
from .client import AIClient, get_client
from .learning import LearningStore, get_store


SYSTEM = """You are Bastionscan AI, an enterprise application-security analyst.
You help banks, ecommerce, and SaaS companies harden systems they own.
Be precise, never alarmist. Prefer concrete remediations over generic advice.
You learn from operator feedback: treat listed false positives as lower priority
and confirmed true positives as higher priority.
Vertical context matters: banking (PCI, transfer fraud), ecommerce (checkout,
PII), SaaS (tenancy, admin SSO), scam (phishing kit residue).
Output JSON with keys:
  summary (string, 2-4 sentences),
  top_priorities (array of {title, why, effort}),
  vertical_advice (string),
  false_positive_risks (array of strings — findings that might be noise),
  confidence (0-1 number).
"""


async def enrich_with_ai(
    scan: ScanResult,
    analysis: RiskAnalysis,
    *,
    vertical: str = "general",
    client: AIClient | None = None,
    store: LearningStore | None = None,
) -> dict[str, Any] | None:
    client = client or get_client()
    store = store or get_store()
    if not client.enabled:
        return _offline_insights(analysis, vertical, store)

    open_findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "category": f.category,
            "detail": (f.detail or "")[:280],
        }
        for f in scan.findings
        if f.status in ("fail", "warn")
    ][:25]

    lessons = store.few_shot_lessons(10)
    weights = store.finding_weights()

    user = {
        "target": analysis.target,
        "grade": analysis.grade,
        "score": analysis.score,
        "risk_index": analysis.risk_index,
        "risk_level": analysis.risk_level,
        "vertical": vertical,
        "headline": analysis.headline,
        "open_findings": open_findings,
        "learning_weights": {k: weights[k] for k in list(weights)[:40]},
        "past_lessons": lessons,
    }
    import json

    data = await client.chat_json(SYSTEM, json.dumps(user, ensure_ascii=False))
    if not data:
        return _offline_insights(analysis, vertical, store)

    return {
        "provider": client.provider,
        "model": client.model,
        "summary": str(data.get("summary") or analysis.headline),
        "top_priorities": data.get("top_priorities") or [],
        "vertical_advice": str(data.get("vertical_advice") or ""),
        "false_positive_risks": data.get("false_positive_risks") or [],
        "confidence": float(data.get("confidence") or 0.6),
        "learning_lessons_used": len(lessons),
        "source": "llm",
    }


def _offline_insights(
    analysis: RiskAnalysis,
    vertical: str,
    store: LearningStore,
) -> dict[str, Any]:
    """Deterministic fallback when no API key — still uses learning weights."""
    priorities = [
        {"title": r.title, "why": r.detail[:200], "effort": r.effort}
        for r in analysis.remediation[:5]
    ]
    advice = {
        "banking": "Prioritize transfer/auth APIs, admin SSO+MFA, and block data-exfil paths before PCI evidence collection.",
        "ecommerce": "Harden checkout and admin; kill debug/.env; rate-limit account APIs that leak customers.",
        "saas": "Enforce tenant isolation on /api/v1/users|orgs; disable GraphQL introspection; metrics behind auth.",
        "scam": "Treat kit leftovers (.env, backups, open admin) as incident response, not hygiene.",
        "general": "Fix critical/high findings first; verify ownership before any Active DAST retest.",
    }.get(vertical, "Fix critical/high findings first.")

    lessons = store.few_shot_lessons(5)
    return {
        "provider": "offline",
        "model": "rules+learning",
        "summary": analysis.headline,
        "top_priorities": priorities,
        "vertical_advice": advice,
        "false_positive_risks": [
            f"Historical FP pressure on {fid}"
            for fid, w in store.finding_weights().items()
            if w < 0.7
        ][:5],
        "confidence": 0.45,
        "learning_lessons_used": len(lessons),
        "source": "offline",
    }
