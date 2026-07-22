"""Environment-driven configuration for the analysis brain."""

from __future__ import annotations

import os


def _normalize_url(value: str) -> str:
    """Accept a full URL or a bare host/host:port (as Render's fromService
    provides) and return a usable base URL.

    A value carrying an explicit port (e.g. ``bastionscan-engine:10000``) is
    Render internal service networking, which speaks plain HTTP. A bare hostname
    with no port (e.g. ``api.example.com``) is treated as a public HTTPS host.
    """
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        host_only = value.split("/", 1)[0]
        scheme = "http://" if ":" in host_only else "https://"
        value = scheme + value
    return value.rstrip("/")


class Config:
    def __init__(self) -> None:
        self.engine_url: str = _normalize_url(os.getenv("ENGINE_URL", "http://localhost:8080"))
        self.port: int = int(os.getenv("PORT", "8090"))
        self.allowed_origins: list[str] = [
            o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
        ]
        self.engine_timeout: float = float(os.getenv("ENGINE_TIMEOUT", "90"))

        # Live vulnerability feed (OSV.dev). Enrichment is best-effort: if the
        # feed is disabled, slow, or unreachable, the curated database still
        # produces results, so a scan never depends on it.
        self.osv_enabled: bool = os.getenv("OSV_ENABLED", "true").strip().lower() not in ("0", "false", "no")
        self.osv_url: str = _normalize_url(os.getenv("OSV_URL", "https://api.osv.dev"))
        self.osv_timeout: float = float(os.getenv("OSV_TIMEOUT", "6"))
        self.osv_cache_ttl: float = float(os.getenv("OSV_CACHE_TTL", "21600"))  # 6h

        self.version: str = "0.1.0"


config = Config()
