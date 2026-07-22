"""AI intelligence layer: multi-provider LLM + continuous learning from scans."""

from .client import AIClient, get_client
from .insights import enrich_with_ai
from .learning import LearningStore, get_store

__all__ = ["AIClient", "get_client", "enrich_with_ai", "LearningStore", "get_store"]
