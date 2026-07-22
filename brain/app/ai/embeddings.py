"""Local + optional remote embeddings for RAG.

DeepSeek does not expose a public embeddings API, so we ship a strong local
hashing embedder (no TensorFlow required on the free Render tier). When
`EMBEDDING_BASE_URL` + key are set (OpenAI-compatible), we use remote vectors
and fall back to local on failure.

The interface is model-agnostic so you can later plug in TensorFlow /
sentence-transformers offline workers without changing callers.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Sequence

import httpx

from ..config import config

_TOKEN = re.compile(r"[a-z0-9_./:-]{2,}", re.I)


def tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN.findall(text or "") if t]


class HashingEmbedder:
    """Feature-hashing bag-of-words embedding — deterministic, dependency-free.

    Dimension is fixed (default 384). Good enough for retrieval over security
    findings, feedback notes, and short knowledge docs.
    """

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        toks = tokenize(text)
        if not toks:
            return vec
        for t in toks:
            h = int(hashlib.md5(t.encode("utf-8")).hexdigest(), 16)
            idx = h % self.dim
            sign = 1.0 if (h // self.dim) % 2 == 0 else -1.0
            # subword boost for finding ids like active.sqli
            vec[idx] += sign
            if "." in t:
                for part in t.split("."):
                    if len(part) < 2:
                        continue
                    hp = int(hashlib.md5(part.encode()).hexdigest(), 16)
                    vec[hp % self.dim] += 0.5 * (1.0 if (hp // self.dim) % 2 == 0 else -1.0)
        return _l2_normalize(vec)

    def embed_batch(self, texts: Sequence[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


async def embed_texts(texts: list[str]) -> list[list[float]]:
    """Prefer remote embeddings when configured; else local hashing."""
    if not texts:
        return []
    if config.embedding_enabled and config.embedding_api_key:
        remote = await _remote_embed(texts)
        if remote is not None:
            return remote
    emb = HashingEmbedder(config.embedding_dim)
    return emb.embed_batch(texts)


async def embed_query(text: str) -> list[float]:
    return (await embed_texts([text]))[0]


async def _remote_embed(texts: list[str]) -> list[list[float]] | None:
    url = f"{config.embedding_base_url.rstrip('/')}/embeddings"
    headers = {
        "Authorization": f"Bearer {config.embedding_api_key}",
        "Content-Type": "application/json",
    }
    payload = {"model": config.embedding_model, "input": texts}
    try:
        async with httpx.AsyncClient(timeout=config.ai_timeout) as client:
            resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code >= 400:
            return None
        data = resp.json()
        items = data.get("data") or []
        # Sort by index if present
        items = sorted(items, key=lambda x: x.get("index", 0))
        out = []
        for it in items:
            v = it.get("embedding")
            if isinstance(v, list):
                out.append([float(x) for x in v])
        return out if len(out) == len(texts) else None
    except Exception:  # noqa: BLE001
        return None


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _l2_normalize(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec))
    if n == 0:
        return vec
    return [x / n for x in vec]
