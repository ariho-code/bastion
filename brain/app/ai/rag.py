"""Retrieval-Augmented Generation store for Bastionscan.

Indexes:
  - operator feedback lessons
  - past scan summaries
  - curated security knowledge (banking / ecommerce / saas / scam)
  - finding-level notes

Retrieval is cosine similarity over embeddings. Used by AI insights and the
streaming chat brain so answers are grounded in *this platform's* history —
not generic LLM memory alone.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .embeddings import cosine, embed_query, embed_texts
from .learning import get_store


# Curated knowledge — always available even on a fresh deploy.
_SEED_DOCS: list[dict[str, str]] = [
    {
        "id": "kb-banking-1",
        "kind": "knowledge",
        "vertical": "banking",
        "text": (
            "Banking AppSec: protect transfer and beneficiary APIs with step-up MFA, "
            "idempotency keys, and anomaly velocity checks. Never expose admin/backoffice "
            "without SSO+MFA. Disable GraphQL introspection in production. "
            "Open Banking OIDC discovery must not leak internal client secrets."
        ),
    },
    {
        "id": "kb-ecommerce-1",
        "kind": "knowledge",
        "vertical": "ecommerce",
        "text": (
            "Ecommerce AppSec: checkout and cart endpoints are high-value for fraud. "
            "Rate-limit account enumeration on login/register. Remove phpinfo, .env, and "
            "store-config.json from production. Magento/WooCommerce admin must not be "
            "public without WAF + MFA. Customer/order APIs need authz per tenant."
        ),
    },
    {
        "id": "kb-saas-1",
        "kind": "knowledge",
        "vertical": "saas",
        "text": (
            "SaaS AppSec: enforce tenant isolation on /api/v1/users|orgs|tenants. "
            "IDOR is the top class of bug. Metrics and actuators must be authenticated. "
            "Invite links expire and bind to email. Prefer RS256 JWT with explicit aud/iss."
        ),
    },
    {
        "id": "kb-scam-1",
        "kind": "knowledge",
        "vertical": "scam",
        "text": (
            "Scam defense: young domains + AI/crypto lexical names + dead origins are "
            "high confidence disposable kits. Never ask for seed phrases. Brand "
            "impersonation + password forms = credential phishing. Report and sinkhole."
        ),
    },
    {
        "id": "kb-dast-safety-1",
        "kind": "knowledge",
        "vertical": "general",
        "text": (
            "Active DAST safety: Bastionscan only runs intrusive probes after DNS "
            "ownership verification. Detection uses canaries and fingerprints — not "
            "data exfiltration or volumetric DDoS. Use scope excludePaths for payment "
            "rails. Prefer SafeMode. Resilience tests send few sequential requests to "
            "check rate-limit headers, never flood."
        ),
    },
    {
        "id": "kb-sqli-1",
        "kind": "knowledge",
        "vertical": "general",
        "text": (
            "SQL injection remediation: parameterized queries / prepared statements "
            "everywhere. ORM alone is not enough for raw SQL. Error messages must not "
            "leak SQLSTATE or stack traces to clients."
        ),
    },
    {
        "id": "kb-xss-1",
        "kind": "knowledge",
        "vertical": "general",
        "text": (
            "XSS remediation: context-aware output encoding, CSP with nonces, avoid "
            "dangerouslySetInnerHTML. Reflected XSS canaries prove unencoded sinks."
        ),
    },
    {
        "id": "kb-csrf-1",
        "kind": "knowledge",
        "vertical": "general",
        "text": (
            "CSRF: anti-CSRF tokens on state-changing forms, SameSite cookies, Origin "
            "checks. Login and payment forms are priority."
        ),
    },
]


class RAGStore:
    def __init__(self, root: Path | None = None) -> None:
        store = get_store()
        self.root = root or (store.root / "rag")
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.jsonl"
        self._lock = threading.Lock()
        self._cache: list[dict[str, Any]] | None = None
        self._ensure_seed()

    def _ensure_seed(self) -> None:
        if self.index_path.exists() and self.index_path.stat().st_size > 0:
            return
        # Sync seed with zero vectors; re-embed lazily on first retrieve.
        for doc in _SEED_DOCS:
            self._append_raw(
                {
                    "id": doc["id"],
                    "kind": doc["kind"],
                    "vertical": doc.get("vertical", "general"),
                    "text": doc["text"],
                    "ts": time.time(),
                    "embedding": None,
                }
            )

    def _append_raw(self, row: dict[str, Any]) -> None:
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with self._lock:
            with self.index_path.open("a", encoding="utf-8") as f:
                f.write(line)
            self._cache = None

    def _load(self) -> list[dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        rows: list[dict[str, Any]] = []
        if not self.index_path.exists():
            self._cache = rows
            return rows
        with self._lock:
            text = self.index_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict) and row.get("text"):
                    rows.append(row)
            except json.JSONDecodeError:
                continue
        self._cache = rows
        return rows

    async def upsert(
        self,
        text: str,
        *,
        kind: str = "note",
        vertical: str = "general",
        meta: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        if len(text) > 4000:
            text = text[:4000]
        emb = (await embed_texts([text]))[0]
        rid = doc_id or str(uuid.uuid4())
        row = {
            "id": rid,
            "kind": kind,
            "vertical": vertical,
            "text": text,
            "ts": time.time(),
            "embedding": emb,
            "meta": meta or {},
        }
        self._append_raw(row)
        return rid

    async def index_scan_summary(
        self,
        *,
        target: str,
        vertical: str,
        grade: str,
        risk_level: str,
        headline: str,
        finding_titles: list[str],
        verified: bool,
    ) -> None:
        text = (
            f"Scan of {target} vertical={vertical} grade={grade} risk={risk_level} "
            f"verified={verified}. {headline}. Open issues: {', '.join(finding_titles[:20])}."
        )
        await self.upsert(text, kind="scan", vertical=vertical, meta={"target": target})

    async def index_feedback(
        self,
        *,
        finding_id: str,
        label: str,
        target: str,
        note: str,
    ) -> None:
        text = (
            f"Operator labeled finding {finding_id} as {label} on {target}. {note}".strip()
        )
        await self.upsert(
            text,
            kind="feedback",
            vertical="general",
            meta={"finding_id": finding_id, "label": label},
        )

    async def retrieve(
        self,
        query: str,
        *,
        vertical: str = "general",
        top_k: int = 6,
        kinds: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        rows = self._load()
        if not rows:
            return []
        # Embed any rows still missing vectors (seed docs).
        missing = [r for r in rows if not r.get("embedding")]
        if missing:
            vectors = await embed_texts([str(r["text"]) for r in missing])
            for r, v in zip(missing, vectors):
                r["embedding"] = v
            # Persist rewritten index occasionally (best-effort rewrite).
            self._rewrite(rows)

        q = await embed_query(query)
        scored: list[tuple[float, dict[str, Any]]] = []
        for r in rows:
            emb = r.get("embedding")
            if not isinstance(emb, list):
                continue
            if kinds and r.get("kind") not in kinds:
                continue
            score = cosine(q, emb)
            # Soft boost same vertical knowledge
            if vertical and r.get("vertical") == vertical:
                score += 0.05
            scored.append((score, r))
        scored.sort(key=lambda x: x[0], reverse=True)
        out = []
        for score, r in scored[:top_k]:
            if score < 0.05:
                continue
            out.append(
                {
                    "id": r.get("id"),
                    "kind": r.get("kind"),
                    "vertical": r.get("vertical"),
                    "text": r.get("text"),
                    "score": round(score, 4),
                    "meta": r.get("meta") or {},
                }
            )
        return out

    def _rewrite(self, rows: list[dict[str, Any]]) -> None:
        with self._lock:
            with self.index_path.open("w", encoding="utf-8") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            self._cache = rows

    def stats(self) -> dict[str, Any]:
        rows = self._load()
        by_kind: dict[str, int] = {}
        for r in rows:
            k = str(r.get("kind") or "?")
            by_kind[k] = by_kind.get(k, 0) + 1
        return {"documents": len(rows), "by_kind": by_kind, "path": str(self.index_path)}


_rag: RAGStore | None = None


def get_rag() -> RAGStore:
    global _rag
    if _rag is None:
        _rag = RAGStore()
    return _rag
