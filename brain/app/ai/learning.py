"""Persistent learning store: scans, human feedback, and weight hints.

The platform improves by recording every assessed scan and every false/true
positive label operators submit. Weight hints derived from feedback are applied
as soft multipliers in the risk analyzer and as few-shot context for the AI.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any


class LearningStore:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or os.getenv("BASTION_LEARNING_DIR", "/tmp/bastion-learning"))
        self.root.mkdir(parents=True, exist_ok=True)
        self.scans_path = self.root / "scans.jsonl"
        self.feedback_path = self.root / "feedback.jsonl"
        self.weights_path = self.root / "finding_weights.json"
        self._lock = threading.Lock()
        self._weights: dict[str, float] | None = None

    # --- scans ---------------------------------------------------------------

    def record_scan(
        self,
        *,
        target: str,
        profile: str,
        vertical: str,
        grade: str,
        score: int,
        risk_index: int,
        risk_level: str,
        findings: list[dict[str, Any]],
        verified: bool,
        tenant: str = "default",
        ai_summary: str | None = None,
    ) -> str:
        sid = str(uuid.uuid4())
        row = {
            "id": sid,
            "ts": time.time(),
            "tenant": tenant,
            "target": target,
            "profile": profile,
            "vertical": vertical,
            "grade": grade,
            "score": score,
            "risk_index": risk_index,
            "risk_level": risk_level,
            "verified": verified,
            "finding_ids": [f.get("id") for f in findings if f.get("status") in ("fail", "warn")],
            "finding_count": len(findings),
            "open_count": sum(1 for f in findings if f.get("status") in ("fail", "warn")),
            "ai_summary": ai_summary,
        }
        self._append(self.scans_path, row)
        return sid

    def list_scans(self, *, tenant: str = "default", limit: int = 50) -> list[dict[str, Any]]:
        rows = self._read_jsonl(self.scans_path)
        rows = [r for r in rows if r.get("tenant", "default") == tenant]
        rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return rows[:limit]

    # --- feedback (human-in-the-loop learning) ------------------------------

    def record_feedback(
        self,
        *,
        finding_id: str,
        label: str,  # true_positive | false_positive | fixed | ignore
        target: str = "",
        note: str = "",
        scan_id: str = "",
        tenant: str = "default",
    ) -> dict[str, Any]:
        label = label.strip().lower().replace("-", "_")
        if label not in ("true_positive", "false_positive", "fixed", "ignore"):
            raise ValueError("label must be true_positive|false_positive|fixed|ignore")
        row = {
            "id": str(uuid.uuid4()),
            "ts": time.time(),
            "tenant": tenant,
            "finding_id": finding_id,
            "label": label,
            "target": target,
            "note": note[:500],
            "scan_id": scan_id,
        }
        self._append(self.feedback_path, row)
        self._recompute_weights()
        return row

    def feedback_stats(self) -> dict[str, Any]:
        rows = self._read_jsonl(self.feedback_path)
        by_label: dict[str, int] = defaultdict(int)
        by_finding: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for r in rows:
            by_label[r.get("label", "?")] += 1
            fid = r.get("finding_id") or "?"
            by_finding[fid][r.get("label", "?")] += 1
        return {
            "total": len(rows),
            "by_label": dict(by_label),
            "by_finding": {k: dict(v) for k, v in list(by_finding.items())[:80]},
            "weights": self.finding_weights(),
        }

    def finding_weights(self) -> dict[str, float]:
        if self._weights is None:
            self._weights = self._load_weights()
        return dict(self._weights)

    def weight_for(self, finding_id: str) -> float:
        """Soft multiplier: <1 dampens noisy FPs, >1 boosts confirmed TPs."""
        return self.finding_weights().get(finding_id, 1.0)

    def few_shot_lessons(self, limit: int = 12) -> list[str]:
        """Human-readable lessons for AI system prompts."""
        rows = self._read_jsonl(self.feedback_path)
        rows.sort(key=lambda r: r.get("ts", 0), reverse=True)
        lessons: list[str] = []
        for r in rows[: limit * 3]:
            fid = r.get("finding_id", "")
            label = r.get("label", "")
            note = (r.get("note") or "").strip()
            if label == "false_positive":
                lessons.append(f"Finding {fid} was a FALSE POSITIVE on {r.get('target','')}. {note}".strip())
            elif label == "true_positive":
                lessons.append(f"Finding {fid} was confirmed TRUE POSITIVE on {r.get('target','')}. {note}".strip())
            if len(lessons) >= limit:
                break
        return lessons

    # --- internals -----------------------------------------------------------

    def _recompute_weights(self) -> None:
        rows = self._read_jsonl(self.feedback_path)
        scores: dict[str, list[float]] = defaultdict(list)
        for r in rows:
            fid = r.get("finding_id") or ""
            if not fid:
                continue
            label = r.get("label")
            if label == "false_positive":
                scores[fid].append(0.45)
            elif label == "true_positive":
                scores[fid].append(1.35)
            elif label == "fixed":
                scores[fid].append(1.0)
            elif label == "ignore":
                scores[fid].append(0.7)
        weights = {fid: max(0.25, min(2.0, sum(v) / len(v))) for fid, v in scores.items()}
        with self._lock:
            self._weights = weights
            self.weights_path.write_text(json.dumps(weights, indent=2), encoding="utf-8")

    def _load_weights(self) -> dict[str, float]:
        if not self.weights_path.exists():
            return {}
        try:
            data = json.loads(self.weights_path.read_text(encoding="utf-8"))
            return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    def _append(self, path: Path, row: dict[str, Any]) -> None:
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with self._lock:
            with path.open("a", encoding="utf-8") as f:
                f.write(line)

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self._lock:
            text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    out.append(row)
            except json.JSONDecodeError:
                continue
        return out


_store: LearningStore | None = None


def get_store() -> LearningStore:
    global _store
    if _store is None:
        from ..config import config

        _store = LearningStore(config.learning_dir)
    return _store
