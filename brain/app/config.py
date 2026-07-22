"""Environment-driven configuration for the analysis brain."""

from __future__ import annotations

import os


class Config:
    def __init__(self) -> None:
        self.engine_url: str = os.getenv("ENGINE_URL", "http://localhost:8080").rstrip("/")
        self.port: int = int(os.getenv("PORT", "8090"))
        self.allowed_origins: list[str] = [
            o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
        ]
        self.engine_timeout: float = float(os.getenv("ENGINE_TIMEOUT", "90"))
        self.version: str = "0.1.0"


config = Config()
