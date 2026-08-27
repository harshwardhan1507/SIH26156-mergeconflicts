"""Abstract base class for enrichment plugins."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class EnrichmentPlugin(ABC):
    name: str = ''
    version: str = '1.0.0'

    @abstractmethod
    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich the UES event in-place or return a modified copy.
        Must always return a valid UES event dict.
        This method MUST be safe to call with network access disabled.
        """
