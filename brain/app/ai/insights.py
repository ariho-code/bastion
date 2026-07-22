"""AI enrichment with RAG retrieval + ML false-positive ranking."""

from __future__ import annotations

import json
from typing import Any

from ..models import RiskAnalysis, ScanResult
from .client import AIClient, get_client
from .learning import LearningStore, get_store
from .ml_model import get_fp_model
from .rag import get_rag


SYSTEM = """You are Bastionscan AI, an enterprise application-security analyst with RAG memory.
You help banks, ecommerce, and SaaS companies harden systems they own.
You receive retrieved context from past scans, operator feedback, and security knowledge.
Ground your advice in that context when relevant. Cite lesson themes, not document IDs.
Be precise, never alarmist. Prefer concrete remediations.
Active DAST is ownership-gated; never recommend attacking third parties.
Volumetric DDoS is out of scope — recommend staged load tests instead.
Output JSON with keys:
  summary (string, 2-4 sentences),
  top_priorities (array of {title, why, effort}),
  vertical_advice (string),
  false_positive_risks (array of strings),
  confidence (0-1 number),
  rag_citations (array of short strings describing used context).
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
    rag = get_rag()
    fp_model = get_fp_model()

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

    query = (
        f"{vertical} {analysis.target} {analysis.headline} "
        + " ".join(f["id"] + " " + f["title"] for f in open_findings[:12])
    )
    rag_hits = await rag.retrieve(query, vertical=vertical, top_k=6)
    lessons = store.few_shot_lessons(10)
    weights = store.finding_weights()
    ml_fps = fp_model.rank_fp_risks(open_findings, vertical=vertical)

    if not client.enabled:
        offline = _offline_insights(analysis, vertical, store, rag_hits, ml_fps)
        return offline

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
        "rag_context": [{"score": h["score"], "kind": h["kind"], "text": h["text"][:500]} for h in rag_hits],
        "ml_false_positive_hints": ml_fps,
    }

    data = await client.chat_json(SYSTEM, json.dumps(user, ensure_ascii=False))
    if not data:
        return _offline_insights(analysis, vertical, store, rag_hits, ml_fps)

    fps = data.get("false_positive_risks") or []
    if isinstance(fps, list):
        fps = list(fps) + [x for x in ml_fps if x not in fps]
    else:
        fps = ml_fps

    return {
        "provider": client.provider,
        "model": client.model,
        "summary": str(data.get("summary") or analysis.headline),
        "top_priorities": data.get("top_priorities") or [],
        "vertical_advice": str(data.get("vertical_advice") or ""),
        "false_positive_risks": fps[:10],
        "confidence": float(data.get("confidence") or 0.6),
        "learning_lessons_used": len(lessons),
        "rag_hits": len(rag_hits),
        "rag_citations": data.get("rag_citations") or [h["text"][:120] for h in rag_hits[:3]],
        "source": "llm+rag",
    }


def _offline_insights(
    analysis: RiskAnalysis,
    vertical: str,
    store: LearningStore,
    rag_hits: list[dict[str, Any]],
    ml_fps: list[str],
) -> dict[str, Any]:
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

    # Blend RAG knowledge into vertical advice when available.
    kb = next((h["text"] for h in rag_hits if h.get("kind") == "knowledge"), "")
    if kb:
        advice = advice + " " + kb[:280]

    lessons = store.few_shot_lessons(5)
    fps = ml_fps + [
        f"Historical FP pressure on {fid}"
        for fid, w in store.finding_weights().items()
        if w < 0.7
    ]
    return {
        "provider": "offline",
        "model": "rules+rag+ml",
        "summary": analysis.headline,
        "top_priorities": priorities,
        "vertical_advice": advice,
        "false_positive_risks": fps[:8],
        "confidence": 0.5 if rag_hits else 0.4,
        "learning_lessons_used": len(lessons),
        "rag_hits": len(rag_hits),
        "rag_citations": [h["text"][:120] for h in rag_hits[:3]],
        "source": "offline+rag",
    }


async def chat_with_rag(
    message: str,
    *,
    target: str = "",
    vertical: str = "general",
    scan_context: dict[str, Any] | None = None,
    client: AIClient | None = None,
) -> dict[str, Any]:
    """Conversational security assistant grounded in RAG + optional scan context."""
    client = client or get_client()
    rag = get_rag()
    hits = await rag.retrieve(f"{vertical} {target} {message}", vertical=vertical, top_k=8)
    context_blocks = "\n---\n".join(
        f"[{h['kind']}|{h['score']}] {h['text']}" for h in hits
    )
    system = (
        "You are Bastionscan Copilot. Answer using retrieved platform memory when relevant. "
        "Only discuss authorized testing of owner-verified systems. Refuse requests to attack "
        "third parties or run volumetric DDoS. Be concise and actionable."
    )
    user = (
        f"Vertical: {vertical}\nTarget: {target or 'n/a'}\n"
        f"Scan context: {json.dumps(scan_context or {})[:2000]}\n"
        f"Retrieved memory:\n{context_blocks}\n\nUser question: {message}"
    )
    if not client.enabled:
        # Offline extractive answer from RAG
        if hits:
            return {
                "reply": "Based on platform memory:\n\n"
                + "\n\n".join(h["text"][:400] for h in hits[:3]),
                "rag_hits": len(hits),
                "source": "offline+rag",
            }
        return {
            "reply": "AI is offline (no API key). Set DEEPSEEK_API_KEY on the brain service. "
            "RAG has no matching memory yet — run scans and label findings to teach it.",
            "rag_hits": 0,
            "source": "offline",
        }
    text = await client.chat(system, user, temperature=0.3, max_tokens=900)
    return {
        "reply": text or "No response from model.",
        "rag_hits": len(hits),
        "citations": [h["text"][:160] for h in hits[:4]],
        "source": "llm+rag",
        "provider": client.provider,
        "model": client.model,
    }
