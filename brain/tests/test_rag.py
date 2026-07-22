"""RAG retrieval + local embeddings tests (no network)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.ai.embeddings import HashingEmbedder, cosine
from app.ai.learning import LearningStore
from app.ai.ml_model import FPModel
from app.ai.rag import RAGStore


def test_rag_retrieve_seed_knowledge(tmp_path: Path) -> None:
    rag = RAGStore(tmp_path / "rag")
    hits = asyncio.run(rag.retrieve("SQL injection prepared statements", vertical="general", top_k=4))
    assert hits, "seed knowledge should be retrievable"
    blob = " ".join(h["text"].lower() for h in hits)
    assert "sql" in blob or "parameter" in blob or "injection" in blob


def test_rag_indexes_feedback(tmp_path: Path) -> None:
    rag = RAGStore(tmp_path / "rag2")
    asyncio.run(
        rag.index_feedback(
            finding_id="active.xss",
            label="false_positive",
            target="shop.example",
            note="reflection was HTML-encoded",
        )
    )
    hits = asyncio.run(rag.retrieve("xss false positive encoded", top_k=5))
    blob = " ".join(h["text"].lower() for h in hits)
    assert "false_positive" in blob or "xss" in blob


def test_hashing_embed_stable() -> None:
    e = HashingEmbedder(64)
    a = e.embed("active.sqli database error")
    b = e.embed("active.sqli database error")
    assert a == b
    assert cosine(a, b) > 0.99


def test_fp_model_trains(tmp_path: Path) -> None:
    store = LearningStore(tmp_path)
    for _ in range(4):
        store.record_feedback(finding_id="active.xss", label="false_positive")
        store.record_feedback(finding_id="active.sqli", label="true_positive")
    model = FPModel(path=tmp_path / "fp.json")
    stats = model.train_from_feedback(feedback_path=store.feedback_path)
    assert stats.get("trained") is True
    p_xss = model.predict_proba("active.xss")
    p_sqli = model.predict_proba("active.sqli")
    assert p_xss > p_sqli
