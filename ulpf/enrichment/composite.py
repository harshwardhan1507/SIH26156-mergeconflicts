"""
Composite Enrichment Plugin.

Chains multiple EnrichmentPlugin instances in order.
Each plugin receives the output of the previous one.

Usage:
    from ulpf.enrichment.composite import CompositeEnrichment
    from ulpf.enrichment.ip_enrichment import IPEnrichmentPlugin

    enricher = CompositeEnrichment([
        IPEnrichmentPlugin(),
        # Add more plugins here as needed
    ])
    ues_event = enricher.enrich(ues_event)
"""
from __future__ import annotations

import logging
from typing import Any

from ulpf.enrichment.base import EnrichmentPlugin

logger = logging.getLogger(__name__)


class CompositeEnrichment(EnrichmentPlugin):
    """
    Chains multiple EnrichmentPlugin instances sequentially.
    If any individual plugin fails, the error is logged and the chain continues.
    """

    name = "composite"
    version = "1.0.0"

    def __init__(self, plugins: list[EnrichmentPlugin]) -> None:
        self.plugins = plugins
        logger.info(
            "CompositeEnrichment initialized with plugins: %s",
            [p.name for p in plugins],
        )

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        for plugin in self.plugins:
            try:
                event = plugin.enrich(event)
            except Exception as exc:
                logger.warning(
                    "Enrichment plugin %s failed for event %s: %s",
                    plugin.name,
                    event.get("event_id", "?"),
                    exc,
                )
        return event
