"""
GeoIP Enrichment Service

Stub service — geoip2 module has been removed.
Returns events unchanged (pass-through).
"""

from __future__ import annotations

from pathlib import Path

from core.config import get_settings
from core.logging import get_logger
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)

# Log once at import time
logger.info("GeoIP enrichment disabled (geoip2 module removed)")


class GeoIPEnrichmentService:
    """
    Stub GeoIP enrichment service.

    The geoip2 module has been removed. This class preserves the API
    so callers do not need modification, but all methods are no-ops.
    """

    def __init__(self, db_path: Path | None = None):
        self.reader = None

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Return event unchanged (pass-through)."""
        return event

    def enrich_batch(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """Return events unchanged (pass-through)."""
        return events

    def close(self):
        """No-op."""
        pass

    def __del__(self):
        pass
