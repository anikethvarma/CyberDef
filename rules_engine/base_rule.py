"""
Threat Rule Base Class

Abstract base for all deterministic threat detection rules.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Optional

from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class ThreatRule(ABC):
    """Base class for deterministic threat rules."""

    name: str = "base_rule"
    category: str = "unknown"
    family: ThreatFamily = ThreatFamily.INJECTION
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.8
    description: str = ""

    # Fields to check — subclasses list which NormalizedEvent fields to scan
    check_fields: list[str] = ["uri_path"]

    # Compiled regex patterns — set in subclass __init_subclass__
    _compiled_patterns: list[re.Pattern] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "patterns") and cls.patterns:
            cls._compiled_patterns = [
                re.compile(p, re.IGNORECASE) for p in cls.patterns
            ]

    # Override patterns in subclasses
    patterns: list[str] = []

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """
        Check if an event matches this rule.
        Returns ThreatMatch if matched, None otherwise.
        
        For signature-based attacks (INJECTION and CVE_EXPLOIT families),
        only consider events with 2XX or 3XX status codes.
        """
        # Status code filtering for signature-based attacks
        if self.family in (ThreatFamily.INJECTION, ThreatFamily.CVE_EXPLOIT):
            if event.http_status is not None:
                # Only match if status code is 2XX or 3XX
                if not (200 <= event.http_status < 400):
                    return None
        
        for field_name in self.check_fields:
            value = getattr(event, field_name, None)
            if not value:
                continue
            value_str = str(value)
            for pattern in self._compiled_patterns:
                m = pattern.search(value_str)
                if m:
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=value_str[:200],
                        matched_field=field_name,
                        uri=event.uri_path,
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
        return None


class RateBasedRule(ThreatRule):
    """
    Base for rules that need aggregate analysis (rate, count).
    These don't use regex — they operate on event groups.
    """

    threshold: int = 10
    window_field: str = "src_ip"  # Group by this field

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """Rate-based rules don't match individual events — handled by engine."""
        return None

    @abstractmethod
    def check_group(
        self, events: list[NormalizedEvent], group_key: str
    ) -> Optional[ThreatMatch]:
        """Check a group of events for rate-based threats."""
        pass
