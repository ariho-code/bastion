"""Lightweight online ML for false-positive likelihood.

Trains from operator feedback without TensorFlow (Render free tier friendly).
Uses a logistic regression over hashing features of finding id + category +
severity + vertical. Persists weights to disk so the model improves over time.

When you later want TensorFlow/Keras, swap `FPModel.predict_proba` internals —
the public API stays stable.
"""

from __future__ import annotations

import json
import math
import threading
import time
from pathlib import Path
from typing import Any

from .embeddings import HashingEmbedder, tokenize
from .learning import get_store


class FPModel:
    """Binary classifier: P(false_positive | finding features)."""

    def __init__(self, path: Path | None = None, dim: int = 128) -> None:
        store = get_store()
        self.path = path or (store.root / "fp_model.json")
        self.dim = dim
        self.emb = HashingEmbedder(dim)
        self.weights = [0.0] * dim
        self.bias = 0.0
        self.trained_on = 0
        self.updated_at = 0.0
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            w = data.get("weights") or []
            if len(w) == self.dim:
                self.weights = [float(x) for x in w]
                self.bias = float(data.get("bias") or 0.0)
                self.trained_on = int(data.get("trained_on") or 0)
                self.updated_at = float(data.get("updated_at") or 0.0)
        except Exception:  # noqa: BLE001
            pass

    def _save(self) -> None:
        payload = {
            "weights": self.weights,
            "bias": self.bias,
            "trained_on": self.trained_on,
            "updated_at": self.updated_at,
            "dim": self.dim,
        }
        with self._lock:
            self.path.write_text(json.dumps(payload), encoding="utf-8")

    def _features(self, finding_id: str, category: str = "", severity: str = "", vertical: str = "") -> list[float]:
        text = f"{finding_id} {category} {severity} {vertical} {' '.join(tokenize(finding_id))}"
        return self.emb.embed(text)

    @staticmethod
    def _sigmoid(z: float) -> float:
        z = max(-30.0, min(30.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def predict_proba(
        self,
        finding_id: str,
        *,
        category: str = "",
        severity: str = "",
        vertical: str = "",
    ) -> float:
        """Return P(false_positive). Untrained model returns 0.35 neutral-low."""
        if self.trained_on < 3:
            # Blend with learning-store weights if any.
            w = get_store().weight_for(finding_id)
            # weight < 1 means historically FP-ish
            return max(0.05, min(0.95, 1.0 - (w / 2.0)))
        x = self._features(finding_id, category, severity, vertical)
        z = self.bias + sum(wi * xi for wi, xi in zip(self.weights, x))
        return self._sigmoid(z)

    def train_from_feedback(
        self,
        lr: float = 0.15,
        epochs: int = 4,
        *,
        feedback_path: Path | None = None,
    ) -> dict[str, Any]:
        """Retrain on all feedback labels in the learning store."""
        store = get_store()
        path = feedback_path or store.feedback_path
        rows = store._read_jsonl(path)  # noqa: SLF001 — shared jsonl reader
        samples: list[tuple[list[float], float]] = []
        for r in rows:
            label = r.get("label")
            fid = str(r.get("finding_id") or "")
            if not fid:
                continue
            if label == "false_positive":
                y = 1.0
            elif label == "true_positive":
                y = 0.0
            else:
                continue
            x = self._features(fid)
            samples.append((x, y))
        if len(samples) < 2:
            return {"trained": False, "samples": len(samples)}

        w = self.weights[:]
        b = self.bias
        n = len(samples)
        for _ in range(epochs):
            for x, y in samples:
                z = b + sum(wi * xi for wi, xi in zip(w, x))
                p = self._sigmoid(z)
                err = p - y
                for i in range(self.dim):
                    w[i] -= lr * err * x[i]
                b -= lr * err
        self.weights = w
        self.bias = b
        self.trained_on = n
        self.updated_at = time.time()
        self._save()
        return {"trained": True, "samples": n, "updated_at": self.updated_at}

    def rank_fp_risks(
        self,
        findings: list[dict[str, Any]],
        *,
        vertical: str = "general",
        threshold: float = 0.55,
    ) -> list[str]:
        out: list[str] = []
        for f in findings:
            fid = str(f.get("id") or "")
            if not fid:
                continue
            p = self.predict_proba(
                fid,
                category=str(f.get("category") or ""),
                severity=str(f.get("severity") or ""),
                vertical=vertical,
            )
            if p >= threshold:
                out.append(f"{fid} (model FP≈{p:.0%})")
        return out[:8]


_model: FPModel | None = None


def get_fp_model() -> FPModel:
    global _model
    if _model is None:
        _model = FPModel()
    return _model
