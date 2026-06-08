"""
Threat Rule Base Class

Abstract base for all deterministic threat detection rules.
"""

from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from urllib.parse import unquote_plus, urlsplit
from typing import Tuple, List, Dict

from core.logging import get_logger
from rules_engine.models import ThreatFamily, ThreatMatch, ThreatSeverity
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class ThreatRule(ABC):
    """Base class for deterministic threat rules."""

    name: str = "base_rule"
    category: str = "unknown"
    family: ThreatFamily = ThreatFamily.INJECTION
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    confidence: float = 0.8
    description: str = ""
    regex_flags: int = re.IGNORECASE

    # If True, signature-based rules only match on 2xx/3xx responses.
    # Subclasses can override this to False where status should not gate detection.
    enforce_success_status_filter: bool = True

    # Fields to check. Subclasses list which NormalizedEvent fields to scan.
    check_fields: List[str] = ["raw_url"]

    # Compiled regex patterns, set in subclass __init_subclass__.
    _compiled_patterns: List[re.Pattern] = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "patterns") and isinstance(cls.patterns, list) and cls.patterns:
            cls._compiled_patterns = [re.compile(p, cls.regex_flags) for p in cls.patterns]

    # Override patterns in subclasses.
    patterns: List[str] = []

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        """
        Check if an event matches this rule.
        Returns ThreatMatch if matched, None otherwise.
        """
        if (
            self.enforce_success_status_filter
            and self.family in (ThreatFamily.INJECTION, ThreatFamily.CVE_EXPLOIT)
            and event.http_status is not None
            and not (200 <= event.http_status < 300)
        ):
            return None

        for field_name in self.check_fields:
            value = getattr(event, field_name, None)
            if not value:
                continue

            value_str = str(value)

            for pattern in self._compiled_patterns:
                if pattern.search(value_str):
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=value_str[:200],
                        matched_field=field_name,
                        raw_url=event.raw_url,
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                        src_username=event.username,
                    )

        return None


class RateBasedRule(ThreatRule):
    """
    Base for rules that need aggregate analysis, such as rate or count checks.
    These do not use per-event regex matching and are handled by the engine.
    """

    threshold: int = 10
    window_field: str = "src_ip"

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        return None

    @abstractmethod
    def check_group(
        self, events: List[NormalizedEvent], group_key: str
    ) -> ThreatMatch | None:
        """Check a group of events for rate-based threats."""
        pass


class ScoredThreatRule(ThreatRule, ABC):
    """
    Weighted pattern rule for higher-signal detections.

    patterns maps a label to (regex, weight). A match is returned only when
    the accumulated score reaches the rule threshold.
    """

    patterns: Dict[str, Tuple[str, int]] = {}
    threshold: int = 5
    max_payload_length = 4000
    static_extensions = (
        ".css",
        ".js",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )

    _compiled_patterns: Dict[str, Tuple[re.Pattern, int]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "patterns") and isinstance(cls.patterns, dict):
            cls._compiled_patterns = {
                name: (re.compile(regex, cls.regex_flags), weight)
                for name, (regex, weight) in cls.patterns.items()
            }

    @classmethod
    def normalize(cls, value: str) -> str:
        if not value:
            return ""

        try:
            value = unquote_plus(unquote_plus(value))
        except Exception:
            pass

        value = unicodedata.normalize("NFKC", value)
        return value[: cls.max_payload_length]

    @classmethod
    def _is_static_uri(cls, value: str) -> bool:
        path = urlsplit(value).path.lower()
        return path.endswith(cls.static_extensions)

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if (
            self.enforce_success_status_filter
            and event.http_status is not None
            and not (200 <= event.http_status < 300)
        ):
            return None

        score = 0
        matched_names: List[str] = []
        matched_fields: List[str] = []
        evidence_values: List[str] = []

        for field_name in self.check_fields:
            value = getattr(event, field_name, None)
            if not value:
                continue

            value_str = str(value)
            if field_name == "raw_url" and self._is_static_uri(value_str):
                continue

            normalized = self.normalize(value_str)
            for pattern_name, (pattern, weight) in self._compiled_patterns.items():
                if pattern.search(normalized):
                    score += weight
                    matched_names.append(pattern_name)
                    if field_name not in matched_fields:
                        matched_fields.append(field_name)
                    if len(evidence_values) < 3:
                        evidence_values.append(value_str[:200])

        if score < self.threshold:
            return None

        return ThreatMatch(
            event_id=event.event_id,
            rule_name=self.name,
            category=self.category,
            family=self.family,
            severity=self.severity,
            confidence=self.confidence,
            evidence=(
                f"score={score}; patterns={', '.join(matched_names[:8])}; "
                f"evidence={' | '.join(evidence_values)}"
            ),
            matched_field=",".join(matched_fields),
            raw_url=event.raw_url,
            timestamp=event.timestamp,
            src_ip=event.src_ip,
        )
