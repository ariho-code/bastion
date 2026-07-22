"""Thin async client for the Go scanning engine."""

from __future__ import annotations

from typing import Any

import httpx

from .config import config


class EngineError(Exception):
    """Raised when the engine cannot be reached or returns an error."""

    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


async def scan(target: str, profile: str, verified: bool) -> dict[str, Any]:
    """Run a scan on the engine and return its raw JSON result."""
    payload = {"target": target, "profile": profile, "verified": verified}
    try:
        async with httpx.AsyncClient(timeout=config.engine_timeout) as client:
            resp = await client.post(f"{config.engine_url}/v1/scan", json=payload)
    except httpx.HTTPError as exc:
        raise EngineError(f"could not reach scanning engine: {exc}") from exc

    if resp.status_code >= 400:
        detail = _safe_error(resp)
        raise EngineError(detail, status=resp.status_code)
    return resp.json()


async def health() -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{config.engine_url}/health")
        resp.raise_for_status()
        return resp.json()


def _safe_error(resp: httpx.Response) -> str:
    try:
        data = resp.json()
        if isinstance(data, dict) and "error" in data:
            return str(data["error"])
    except Exception:  # noqa: BLE001 - best-effort error extraction
        pass
    return f"engine returned HTTP {resp.status_code}"
