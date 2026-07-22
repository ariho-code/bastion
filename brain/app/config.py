"""Environment-driven configuration for the analysis brain."""

from __future__ import annotations

import os


def _normalize_url(value: str) -> str:
    """Accept a full URL or a bare host (as Render's fromService provides) and
    return a usable base URL."""
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value.rstrip("/")


class Config:
    def __init__(self) -> None:
        self.engine_url: str = _normalize_url(os.getenv("ENGINE_URL", "http://localhost:8080"))
        self.port: int = int(os.getenv("PORT", "8090"))
        self.allowed_origins: list[str] = [
            o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
        ]
        self.engine_timeout: float = float(os.getenv("ENGINE_TIMEOUT", "90"))
        self.version: str = "0.1.0"


config = Config()
