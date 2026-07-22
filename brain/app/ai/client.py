"""OpenAI-compatible multi-provider client.

Default: DeepSeek (DEEPSEEK_API_KEY).
Later swap: Grok/xAI (XAI_API_KEY) or Claude (ANTHROPIC_API_KEY) via AI_PROVIDER.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..config import config

log = logging.getLogger("bastion.ai")


class AIClient:
    """Thin chat-completions client with provider profiles."""

    def __init__(
        self,
        provider: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
    ) -> None:
        self.provider = (provider or config.ai_provider).lower()
        self.api_key = api_key or config.ai_api_key
        self.base_url = (base_url or config.ai_base_url).rstrip("/")
        self.model = model or config.ai_model
        self.timeout = config.ai_timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and config.ai_enabled

    async def chat(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.2,
        max_tokens: int = 1200,
    ) -> str | None:
        if not self.enabled:
            return None
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # Anthropic Messages API is different; for claude we use OpenAI-compat
        # gateways or the official OpenAI-compatible proxy. Native anthropic
        # path is available when base_url points at api.anthropic.com/v1.
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                log.warning("ai provider error %s: %s", resp.status_code, resp.text[:300])
                return None
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return None
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            return content if isinstance(content, str) else None
        except Exception as exc:  # noqa: BLE001
            log.warning("ai request failed: %s", exc)
            return None

    async def chat_json(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.1,
    ) -> dict[str, Any] | None:
        text = await self.chat(
            system + "\nRespond with a single JSON object only. No markdown fences.",
            user,
            temperature=temperature,
            max_tokens=1600,
        )
        if not text:
            return None
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            # Best-effort: extract first {...}
            start, end = text.find("{"), text.rfind("}")
            if start >= 0 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                    return data if isinstance(data, dict) else None
                except json.JSONDecodeError:
                    return None
            return None


_client: AIClient | None = None


def get_client() -> AIClient:
    global _client
    if _client is None:
        _client = AIClient()
    return _client
