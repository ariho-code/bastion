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

        # --- AI intelligence (DeepSeek default; swap via AI_PROVIDER) ----------
        # Providers: deepseek | grok | xai | claude | openai | offline
        self.ai_enabled: bool = os.getenv("AI_ENABLED", "true").strip().lower() not in (
            "0",
            "false",
            "no",
        )
        self.ai_provider: str = os.getenv("AI_PROVIDER", "deepseek").strip().lower()
        self.ai_timeout: float = float(os.getenv("AI_TIMEOUT", "45"))
        self.ai_api_key, self.ai_base_url, self.ai_model = _ai_profile(
            self.ai_provider,
            explicit_key=os.getenv("AI_API_KEY", "").strip(),
            explicit_base=os.getenv("AI_BASE_URL", "").strip(),
            explicit_model=os.getenv("AI_MODEL", "").strip(),
        )
        self.learning_dir: str = os.getenv("BASTION_LEARNING_DIR", "/tmp/bastion-learning")
        self.ai_on_assess: bool = os.getenv("AI_ON_ASSESS", "true").strip().lower() not in (
            "0",
            "false",
            "no",
        )

        # RAG embeddings: local hashing by default; optional OpenAI-compatible remote.
        self.embedding_dim: int = int(os.getenv("EMBEDDING_DIM", "384"))
        self.embedding_api_key: str = (
            os.getenv("EMBEDDING_API_KEY", "").strip()
            or os.getenv("OPENAI_API_KEY", "").strip()
        )
        self.embedding_base_url: str = _normalize_url(
            os.getenv("EMBEDDING_BASE_URL", "https://api.openai.com/v1")
        )
        self.embedding_model: str = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
        self.embedding_enabled: bool = bool(self.embedding_api_key)

        self.version: str = "0.3.0"


def _ai_profile(
    provider: str,
    *,
    explicit_key: str,
    explicit_base: str,
    explicit_model: str,
) -> tuple[str, str, str]:
    """Resolve API key, base URL, and model for the selected provider.

    DeepSeek is the default training/inference brain. Switching to Grok (xAI)
    or Claude later is an env-var change — no code rewrite.
    """
    profiles: dict[str, tuple[str, str, str, str]] = {
        # provider: (env_key_name, default_base, default_model, fallback_env)
        "deepseek": ("DEEPSEEK_API_KEY", "https://api.deepseek.com/v1", "deepseek-chat", ""),
        "grok": ("XAI_API_KEY", "https://api.x.ai/v1", "grok-4.5", "XAI_API_KEY"),
        "xai": ("XAI_API_KEY", "https://api.x.ai/v1", "grok-4.5", ""),
        "claude": (
            "ANTHROPIC_API_KEY",
            "https://api.anthropic.com/v1",
            "claude-sonnet-4-20250514",
            "",
        ),
        "openai": ("OPENAI_API_KEY", "https://api.openai.com/v1", "gpt-4o-mini", ""),
        "offline": ("", "", "offline", ""),
    }
    env_name, base, model, _ = profiles.get(provider, profiles["deepseek"])
    key = explicit_key or (os.getenv(env_name, "").strip() if env_name else "")
    # Grok/xAI alias: also accept GROK_API_KEY
    if not key and provider in ("grok", "xai"):
        key = os.getenv("GROK_API_KEY", "").strip() or os.getenv("XAI_API_KEY", "").strip()
    if not key and provider == "deepseek":
        key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    base = explicit_base or base
    model = explicit_model or model
    return key, base, model


config = Config()
