"""No-op enrichment plugin — returns event unchanged. Default for air-gapped use."""
from __future__ import annotations

from typing import Any

from ulpf.enrichment.base import EnrichmentPlugin


class NoOpEnrichment(EnrichmentPlugin):
    name = 'noop'
    version = '1.0.0'

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        return event
