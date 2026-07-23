"""Multi-provider chat client.

Default: DeepSeek (DEEPSEEK_API_KEY) over the OpenAI-compatible path.
Swap via AI_PROVIDER: Grok/xAI (XAI_API_KEY), OpenAI, or Claude.

Claude is special: Anthropic's Messages API is NOT OpenAI-compatible, so the
"claude" provider is routed through the official `anthropic` SDK (native path)
instead of the chat/completions shim. This lets the security brain run on
Claude — the strongest model for security reasoning — with the current models.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

from ..config import config

log = logging.getLogger("bastion.ai")

# Anthropic's native model IDs never carry a date suffix. Opus 4.8 is the
# default; override with AI_MODEL if you want Sonnet/Haiku for cost/latency.
_ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-8"


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

    @property
    def is_anthropic(self) -> bool:
        """True when the selected provider is Claude (native Messages API)."""
        return self.provider in ("claude", "anthropic") or "anthropic.com" in self.base_url

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
        if self.is_anthropic:
            return await self._chat_anthropic(system, user, max_tokens=max_tokens)
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

    async def _chat_anthropic(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1200,
    ) -> str | None:
        """Native Anthropic Messages API call via the official SDK.

        Anthropic's API is not OpenAI-compatible, so this path is separate. Note
        the current models (Opus 4.8 / Sonnet 5) reject `temperature`, so it is
        never sent — behavior is steered by the prompt. Degrades to None on any
        error (missing SDK, network, refusal) so the caller falls back cleanly.
        """
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            log.warning("anthropic SDK not installed; set AI_PROVIDER to an OpenAI-compatible provider or `pip install anthropic`")
            return None

        # The native SDK uses the default host unless ANTHROPIC_BASE_URL is set;
        # never pass the OpenAI-style ".../v1" base URL here.
        base = os.getenv("ANTHROPIC_BASE_URL", "").strip() or None
        client = AsyncAnthropic(api_key=self.api_key, base_url=base, timeout=self.timeout)
        model = self.model if self.model and self.model.startswith("claude-") else _ANTHROPIC_DEFAULT_MODEL
        try:
            msg = await client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:  # noqa: BLE001 - never let AI errors surface to callers
            log.warning("anthropic request failed: %s", exc)
            return None
        finally:
            await client.close()

        if getattr(msg, "stop_reason", None) == "refusal":
            return None
        parts = [
            block.text
            for block in getattr(msg, "content", [])
            if getattr(block, "type", None) == "text" and getattr(block, "text", None)
        ]
        text = "".join(parts).strip()
        return text or None

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
