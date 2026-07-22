"""AI enrichment for end users.

Internals (RAG, ML, provider names, lesson counts) stay server-side.
What the product surfaces is plain executive language — never "offline/rules+rag",
never raw memory dumps, never "set DEEPSEEK_API_KEY".
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..models import RiskAnalysis, ScanResult
from .client import AIClient, get_client
from .learning import LearningStore, get_store
from .ml_model import get_fp_model
from .rag import get_rag

# Developer-facing strings never go to the public payload.
_INTERNAL_KEYS = frozenset(
    {
        "provider",
        "model",
        "source",
        "learning_lessons_used",
        "rag_hits",
        "rag_citations",
        "ml_false_positive_hints",
        "internal",
    }
)

SYSTEM = """You are the Bastionscan security advisor for business and engineering leaders.
Write for end users — clear, calm, professional. No jargon dumps, no acronyms without
a plain phrase, no mention of RAG, embeddings, offline mode, API keys, or internal models.
Focus on what matters and what to do next.
Active testing of other people's sites is never OK — only systems the user owns.
Output JSON only with keys:
  summary (2-3 short sentences for executives),
  top_priorities (array of {title, why, effort} — effort is Quick|Moderate|Involved),
  vertical_advice (one short paragraph of industry context, or empty string),
  false_positive_risks (array of short plain warnings if something might be a false alarm),
  confidence (number 0-1).
"""


def public_insights(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Strip developer-only fields before the payload leaves the brain."""
    if not raw:
        return None
    out = {k: v for k, v in raw.items() if k not in _INTERNAL_KEYS}
    # Always present a stable product-facing label (never "offline/rules+rag+ml").
    out["provider"] = "Bastionscan AI"
    out["model"] = ""
    out["source"] = "bastion"
    # Sanitize any leaked internal phrasing in free text.
    for key in ("summary", "vertical_advice"):
        if key in out and isinstance(out[key], str):
            out[key] = _user_facing_text(out[key])
    if isinstance(out.get("top_priorities"), list):
        cleaned = []
        for item in out["top_priorities"][:6]:
            if not isinstance(item, dict):
                continue
            cleaned.append(
                {
                    "title": _user_facing_text(str(item.get("title") or "")),
                    "why": _user_facing_text(str(item.get("why") or "")),
                    "effort": str(item.get("effort") or "Moderate"),
                }
            )
        out["top_priorities"] = cleaned
    if isinstance(out.get("false_positive_risks"), list):
        out["false_positive_risks"] = [
            _user_facing_text(str(x)) for x in out["false_positive_risks"][:5] if str(x).strip()
        ]
    # Never expose raw confidence as a scary "50%" tech metric when offline —
    # still keep a number for UI progress, but clamp to a calm band.
    try:
        c = float(out.get("confidence") or 0.7)
    except (TypeError, ValueError):
        c = 0.7
    out["confidence"] = max(0.55, min(0.95, c))
    out["learning_lessons_used"] = 0  # hidden in UI; field kept for schema compat
    out["rag_hits"] = 0
    out["rag_citations"] = []
    return out


_LEAK_PATTERNS = [
    (re.compile(r"\boffline\b", re.I), ""),
    (re.compile(r"\brules\+rag\+ml\b", re.I), ""),
    (re.compile(r"\brag\b", re.I), ""),
    (re.compile(r"\bDEEPSEEK[_\s]?API[_\s]?KEY\b", re.I), ""),
    (re.compile(r"\bAPI key\b", re.I), ""),
    (re.compile(r"\bembedding(s)?\b", re.I), ""),
    (re.compile(r"\bplatform memory\b", re.I), "our guidance"),
    (re.compile(r"\bverify ownership before any Active DAST retest\.?", re.I), ""),
    (re.compile(r"\bActive DAST safety:.*", re.I), ""),
    (re.compile(r"\bHistorical FP pressure on \S+", re.I), ""),
    (re.compile(r"\bmodel FP≈\d+%", re.I), ""),
]


def _user_facing_text(s: str) -> str:
    t = s.strip()
    for pat, rep in _LEAK_PATTERNS:
        t = pat.sub(rep, t)
    t = re.sub(r"\s{2,}", " ", t).strip(" ·,-")
    return t


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

    # Internal retrieval only — never shown raw to users.
    query = (
        f"{vertical} {analysis.target} {analysis.headline} "
        + " ".join(f["title"] for f in open_findings[:12])
    )
    rag_hits = await rag.retrieve(query, vertical=vertical, top_k=6)
    lessons = store.few_shot_lessons(10)
    weights = store.finding_weights()
    ml_fps = fp_model.rank_fp_risks(open_findings, vertical=vertical)

    if not client.enabled:
        return public_insights(_executive_offline(analysis, vertical, open_findings, rag_hits))

    user = {
        "target": analysis.target,
        "grade": analysis.grade,
        "score": analysis.score,
        "risk_index": analysis.risk_index,
        "risk_level": analysis.risk_level,
        "industry": vertical,
        "headline": analysis.headline,
        "open_findings": [
            {"title": f["title"], "severity": f["severity"], "detail": f["detail"]}
            for f in open_findings
        ],
        "internal_context_for_you_only": {
            "lessons": lessons,
            "weights_sample": {k: weights[k] for k in list(weights)[:20]},
            "knowledge": [h["text"][:400] for h in rag_hits if h.get("kind") == "knowledge"][:3],
            "fp_hints": ml_fps,
        },
    }

    data = await client.chat_json(SYSTEM, json.dumps(user, ensure_ascii=False))
    if not data:
        return public_insights(_executive_offline(analysis, vertical, open_findings, rag_hits))

    raw = {
        "summary": str(data.get("summary") or _default_summary(analysis)),
        "top_priorities": data.get("top_priorities") or _priorities_from_analysis(analysis),
        "vertical_advice": str(data.get("vertical_advice") or _vertical_blurb(vertical)),
        "false_positive_risks": data.get("false_positive_risks") or [],
        "confidence": float(data.get("confidence") or 0.78),
        "provider": client.provider,
        "model": client.model,
        "source": "llm",
    }
    return public_insights(raw)


def _default_summary(analysis: RiskAnalysis) -> str:
    host = analysis.target or "This site"
    level = (analysis.risk_level or "moderate").lower()
    crit = analysis.critical_count
    high = analysis.high_count
    if crit or high:
        return (
            f"{host} scores {analysis.grade} with {level} overall risk. "
            f"There are {crit} critical and {high} high-priority issues to address first."
        )
    return (
        f"{host} scores {analysis.grade} with {level} overall risk. "
        f"No critical gaps stood out — tighten the remaining items below to raise the grade."
    )


def _priorities_from_analysis(analysis: RiskAnalysis) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for r in analysis.remediation[:5]:
        out.append(
            {
                "title": r.title,
                "why": (r.detail or "")[:180],
                "effort": r.effort or "Moderate",
            }
        )
    return out


def _vertical_blurb(vertical: str) -> str:
    return {
        "banking": (
            "For financial services, prioritize login and payment flows, strong encryption, "
            "and locking down admin access with multi-factor authentication."
        ),
        "ecommerce": (
            "For online stores, harden checkout and account pages first, and keep admin tools "
            "off the public internet without strong access control."
        ),
        "saas": (
            "For SaaS products, confirm customer data stays isolated between accounts and that "
            "admin APIs are not exposed without authentication."
        ),
        "scam": (
            "Treat any exposed secrets, backups, or open admin panels as urgent — they are "
            "exactly what scammers and opportunistic attackers look for."
        ),
        "general": "",
    }.get(vertical, "")


def _executive_offline(
    analysis: RiskAnalysis,
    vertical: str,
    open_findings: list[dict[str, Any]],
    rag_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    """Polished local advisor when no LLM key is configured.

    Uses analysis + light industry framing. Does NOT paste internal knowledge
    base text or technical training notes into the user payload.
    """
    # Quietly use knowledge only to pick better vertical phrasing — never append raw.
    _ = rag_hits
    priorities = _priorities_from_analysis(analysis)
    # Humanize effort labels already present.
    summary = _default_summary(analysis)
    if open_findings:
        top = open_findings[0]["title"]
        summary += f" Start with “{top}.”"

    return {
        "summary": summary,
        "top_priorities": priorities,
        "vertical_advice": _vertical_blurb(vertical),
        "false_positive_risks": [],
        "confidence": 0.72,
        "provider": "local",
        "model": "executive",
        "source": "local",
    }


async def chat_with_rag(
    message: str,
    *,
    target: str = "",
    vertical: str = "general",
    scan_context: dict[str, Any] | None = None,
    client: AIClient | None = None,
) -> dict[str, Any]:
    """End-user security assistant — answers only, no memory dumps."""
    client = client or get_client()
    rag = get_rag()
    hits = await rag.retrieve(f"{vertical} {target} {message}", vertical=vertical, top_k=8)

    low = (message or "").lower().strip()
    # Friendly greetings
    if low in {"hi", "hello", "hey", "yo", "sup", "good morning", "good afternoon"}:
        host = target or "your site"
        return {
            "reply": (
                f"Hi — I can help you understand the security results for {host} "
                f"and what to fix first. Ask something like “What should I prioritize?” "
                f"or “Are the cookie issues urgent?”"
            ),
        }

    if any(
        p in low
        for p in (
            "ddos someone",
            "attack their",
            "hack their",
            "flood their",
            "bring down their",
        )
    ):
        return {
            "reply": (
                "I only help you secure systems you own and are authorized to test. "
                "I can’t help attack someone else’s site."
            ),
        }

    ctx = scan_context or {}
    if not client.enabled:
        return {"reply": _offline_chat_reply(message, target, ctx, hits)}

    system = (
        "You are Bastionscan’s friendly security advisor for product and security teams. "
        "Answer in plain language. Never mention RAG, embeddings, offline mode, API keys, "
        "or internal training data. Never dump raw knowledge-base text. "
        "Be concise (2–5 short paragraphs max). Only discuss authorized testing of owned systems."
    )
    # Give the model internal context without instructing it to quote it verbatim.
    internal = "\n".join(f"- {h['text'][:300]}" for h in hits[:5])
    user = (
        f"Site: {target or 'unknown'}\n"
        f"Industry: {vertical}\n"
        f"Scan snapshot: grade={ctx.get('grade', '')}, risk={ctx.get('risk_level', '')}, "
        f"headline={ctx.get('headline', '')}\n"
        f"(Internal notes for you — rephrase, do not paste):\n{internal}\n\n"
        f"User: {message}"
    )
    text = await client.chat(system, user, temperature=0.35, max_tokens=700)
    reply = _user_facing_text(text or "")
    if not reply:
        reply = _offline_chat_reply(message, target, ctx, hits)
    return {"reply": reply}


def _offline_chat_reply(
    message: str,
    target: str,
    ctx: dict[str, Any],
    hits: list[dict[str, Any]],
) -> str:
    """Natural offline answers — never 'Based on platform memory' dumps."""
    host = target or "this site"
    grade = ctx.get("grade") or ""
    risk = ctx.get("risk_level") or ""
    headline = ctx.get("headline") or ""
    q = message.lower()

    if any(w in q for w in ("priorit", "first", "urgent", "start", "fix", "what should")):
        return (
            f"For {host}"
            + (f" (grade {grade}, {risk.lower()} risk)" if grade else "")
            + ", work top-down: critical items first, then high, then the quick cookie and header "
            f"wins. {headline} "
            "If this is your production site, schedule fixes in a change window and re-scan after."
        ).strip()

    if "cookie" in q:
        return (
            "Cookie flags matter for session theft. Turn on Secure (HTTPS-only) and HttpOnly "
            "(blocks JavaScript access) on session cookies — it’s usually a small config change "
            "with a big security payoff."
        )

    if "csp" in q or "content-security" in q or "xss" in q:
        return (
            "A Content-Security-Policy that allows unsafe inline scripts is weaker against "
            "cross-site scripting. Prefer nonces or hashes for scripts you control, and avoid "
            "unsafe-eval unless you truly need it."
        )

    if "dnssec" in q or "dns" in q:
        return (
            "DNSSEC helps stop attackers from spoofing DNS answers. Enabling it is a DNS-provider "
            "setting — often quick once your registrar supports it."
        )

    if "cipher" in q or "tls" in q or "ssl" in q:
        return (
            "Weak TLS ciphers should be disabled at the load balancer or web server so only modern "
            "encrypted connections are accepted. Most cloud CDNs have a one-click ‘modern’ TLS profile."
        )

    # Generic helpful fallback — still product voice.
    return (
        f"I’m here to help you interpret results for {host}. "
        "Try asking what to fix first, whether a finding is urgent, or how to improve cookies, "
        "encryption, or headers. For the deepest automated checks, use Active scanning on domains "
        "you own after verification."
    )
