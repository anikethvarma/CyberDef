"""
Rules Engine Models — Pydantic models for deterministic threat detection results.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatFamily(str, Enum):
    INJECTION = "injection"
    AUTH_ACCESS = "auth_access"
    INFO_LEAKAGE = "info_leakage"
    PATH_FILE = "path_file"
    EVASION = "evasion"
    CACHE_REDIRECT = "cache_redirect"
    BOT_SCANNER = "bot_scanner"
    RATE_DOS = "rate_dos"
    CVE_EXPLOIT = "cve_exploit"


class ThreatMatch(BaseModel):
    """A single event matched by a deterministic rule."""
    event_id: UUID
    rule_name: str
    category: str
    family: ThreatFamily
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    matched_field: str
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None


class DeterministicThreat(BaseModel):
    """Grouped threat finding — multiple matches from same IP + rule."""
    threat_id: UUID = Field(default_factory=uuid4)
    category: str
    family: ThreatFamily
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    rule_name: str
    description: str
    match_count: int
    sample_evidence: list[str] = Field(default_factory=list)
    affected_event_ids: list[UUID] = Field(default_factory=list)
    src_ip: Optional[str] = None
    src_ips: list[str] = Field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detection_tier: str = "deterministic"


class DetectionResult(BaseModel):
    """Full result from a Tier 1 deterministic scan."""
    scan_id: UUID = Field(default_factory=uuid4)
    events_scanned: int
    processing_time_ms: int = 0
    matches: list[ThreatMatch] = Field(default_factory=list)
    threats: list[DeterministicThreat] = Field(default_factory=list)
    threats_by_category: dict[str, int] = Field(default_factory=dict)
    threats_by_severity: dict[str, int] = Field(default_factory=dict)
    unique_attacker_ips: list[str] = Field(default_factory=list)
    needs_ai_review: bool = False
    ai_review_reasons: list[str] = Field(default_factory=list)

    @property
    def high_confidence_threats(self) -> list[DeterministicThreat]:
        return [t for t in self.threats if t.confidence >= 0.7]
