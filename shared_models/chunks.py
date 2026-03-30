"""
Chunk Models

Pydantic models for entity-centric behavioral chunks and summaries.
These are the primary input format for AI agents.
"""


from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class TemporalPattern(str, Enum):
    """Detected temporal patterns in event sequences."""
    STEADY = "steady"  # Consistent rate over time
    BURSTY = "bursty"  # Sudden spikes of activity
    BURSTY_THEN_IDLE = "bursty_then_idle"  # Spike followed by quiet
    IDLE_THEN_BURSTY = "idle_then_bursty"  # Quiet followed by spike
    PERIODIC = "periodic"  # Regular intervals
    RANDOM = "random"  # No discernible pattern
    ESCALATING = "escalating"  # Increasing frequency
    DECLINING = "declining"  # Decreasing frequency


class ChunkStrategy(str, Enum):
    """Chunking strategy used to create this chunk."""
    SRC_IP = "src_ip"  # Grouped by source IP
    DST_HOST = "dst_host"  # Grouped by destination host
    USER = "user"  # Grouped by username
    SESSION = "session"  # Grouped by session ID
    CUSTOM = "custom"  # Custom grouping


class TimeWindow(BaseModel):
    """Time window for a behavioral chunk."""
    start: datetime
    end: datetime
    duration_minutes: int
    
    @classmethod
    def from_datetimes(cls, start: datetime, end: datetime) -> "TimeWindow":
        duration = int((end - start).total_seconds() / 60)
        return cls(start=start, end=end, duration_minutes=duration)


class ActorContext(BaseModel):
    """Actor information for a chunk."""
    src_ip: Optional[str] = None
    src_ips: list[str] = Field(default_factory=list)  # If multiple
    username: Optional[str] = None
    hostname: Optional[str] = None
    is_internal: Optional[bool] = None


class TargetContext(BaseModel):
    """Target information for a chunk."""
    dst_ip: Optional[str] = None
    dst_ips: list[str] = Field(default_factory=list)
    dst_host: Optional[str] = None
    dst_hosts: list[str] = Field(default_factory=list)
    unique_target_count: int = 0


class ActivityProfile(BaseModel):
    """Aggregated activity metrics for a chunk."""
    total_events: int
    
    # Action breakdown
    allow_count: int = 0
    deny_count: int = 0
    
    # Authentication related
    auth_success_count: int = 0
    auth_failure_count: int = 0
    
    # Network metrics
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_dst_hosts: int = 0
    unique_ports: int = 0
    
    # Traffic volume
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    
    # Derived metrics
    failure_rate: float = 0.0
    events_per_minute: float = 0.0


class EnvironmentContext(BaseModel):
    """Environment context for a chunk."""
    environment: Optional[str] = None  # PROD, DEV, STAGING
    network_zone: Optional[str] = None  # DMZ, INTERNAL, EXTERNAL
    asset_criticality: Optional[str] = None  # HIGH, MEDIUM, LOW


class BehavioralChunk(BaseModel):
    """
    Entity-centric behavioral chunk.
    Groups related events by entity (IP, user, host) and time window.
    """
    chunk_id: UUID = Field(default_factory=uuid4)
    file_id: UUID
    strategy: ChunkStrategy
    
    # Time context
    time_window: TimeWindow
    
    # Entity context
    actor: ActorContext
    targets: TargetContext
    
    # Activity summary
    activity_profile: ActivityProfile
    
    # Port analysis
    port_traffic: dict[int, int] = Field(default_factory=dict)  # port -> count
    unique_ports: set[int] = Field(default_factory=set)
    ports: list[int] = Field(default_factory=list)  # Ordered by frequency
    port_categories: list[str] = Field(default_factory=list)  # SSH, RDP, HTTP, etc.
    
    # Protocol distribution
    protocol_distribution: dict[str, int] = Field(default_factory=dict)
    
    # Action distribution
    action_distribution: dict[str, int] = Field(default_factory=dict)
    
    # Temporal analysis
    temporal_pattern: TemporalPattern = TemporalPattern.STEADY
    
    # Environment
    context: EnvironmentContext = Field(default_factory=EnvironmentContext)
    
    # Raw events for extended threat analysis
    events: list[Any] = Field(default_factory=list)
    
    # Traceability - list of event IDs that compose this chunk
    source_event_ids: list[UUID] = Field(default_factory=list)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict()


class ChunkSummary(BaseModel):
    """
    Semantic summary of a behavioral chunk.
    This is the ONLY format sent to AI agents.
    """
    chunk_id: UUID
    
    # Human-readable time window
    time_window_str: str  # e.g., "10:00–10:30 UTC"
    duration_minutes: int
    
    # Actor summary
    actor: dict[str, Any]
    
    # Activity profile (structured)
    activity_profile: dict[str, Any]
    
    # Ports accessed
    ports: list[int]
    port_descriptions: list[str]  # e.g., ["SSH (22)", "RDP (3389)"]
    
    # Temporal behavior
    temporal_pattern: str
    temporal_description: str  # Human-readable
    
    # Environment context
    context: dict[str, Any]
    
    # Red flags (deterministically computed)
    red_flags: list[str] = Field(default_factory=list)
    # Threat intelligence context
    threat_indicators: Optional[list[str]] = None
    severity_distribution: Optional[dict[str, int]] = None  # INFO, LOW, MEDIUM, HIGH, CRITICAL counts
    
    # ========== EXTENDED THREAT DETECTION FIELDS ==========
    
    # HTTP/Web attack patterns
    http_methods_seen: Optional[list[str]] = None
    http_status_codes: Optional[dict[str, int]] = None  # Status code -> count
    suspicious_uri_patterns: Optional[list[str]] = None  # SQLi, XSS, path traversal indicators
    user_agents_seen: Optional[list[str]] = None
    http_attack_indicators: Optional[list[str]] = None  # Specific attack signatures detected
    
    # Process/Endpoint behavior
    process_names_seen: Optional[list[str]] = None
    suspicious_processes: Optional[list[str]] = None  # Known malicious or unusual processes
    command_line_patterns: Optional[list[str]] = None  # Suspicious command patterns
    file_operations: Optional[dict[str, int]] = None  # Operation type -> count
    registry_modifications: Optional[list[str]] = None  # Registry keys modified
    
    # Geographic anomalies
    source_countries: Optional[list[str]] = None  # Unique countries seen
    geo_anomaly_detected: bool = False
    geo_anomaly_description: Optional[str] = None  # e.g., "Access from blacklisted country"
    impossible_travel_detected: bool = False  # Same user from distant locations
    
    # DNS patterns
    dns_queries: Optional[list[str]] = None
    suspicious_domains: Optional[list[str]] = None  # DGA, C2, known malicious
    dns_tunneling_indicators: Optional[list[str]] = None
    
    # Email patterns (for email logs)
    email_senders: Optional[list[str]] = None
    suspicious_attachments: Optional[list[str]] = None
    phishing_indicators: Optional[list[str]] = None
    
    # Session tracking
    unique_sessions: int = 0
    session_anomalies: Optional[list[str]] = None  # Session hijacking, anomalous duration
    
    @classmethod
    def from_chunk(cls, chunk: BehavioralChunk) -> "ChunkSummary":
        """
        Create a summary from a behavioral chunk.
        
        This is a basic conversion. The BehaviorSummaryService
        will enrich this with semantic analysis.
        """
        # Format time window
        time_str = (
            f"{chunk.time_window.start.strftime('%H:%M')}–"
            f"{chunk.time_window.end.strftime('%H:%M')} UTC"
        )
        
        # Build actor dict
        actor = {}
        if chunk.actor.src_ip:
            actor["src_ip"] = chunk.actor.src_ip
        if chunk.actor.src_ips:
            actor["src_ips"] = chunk.actor.src_ips
        if chunk.actor.username:
            actor["username"] = chunk.actor.username
        if chunk.actor.is_internal is not None:
            actor["is_internal"] = chunk.actor.is_internal
            
        # Build activity profile dict
        activity = {
            "total_events": chunk.activity_profile.total_events,
            "allow_count": chunk.activity_profile.allow_count,
            "deny_count": chunk.activity_profile.deny_count,
            "unique_targets": chunk.targets.unique_target_count,
            "failure_rate": round(chunk.activity_profile.failure_rate, 2),
        }
        if chunk.activity_profile.auth_failure_count > 0:
            activity["auth_failures"] = chunk.activity_profile.auth_failure_count
            activity["auth_successes"] = chunk.activity_profile.auth_success_count
            
        # Port descriptions
        port_map = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
            3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
        }
        port_descs = [
            f"{port_map.get(p, 'Unknown')} ({p})" for p in chunk.ports[:10]
        ]
        
        # Temporal description
        temporal_map = {
            TemporalPattern.STEADY: "Consistent activity throughout the window",
            TemporalPattern.BURSTY: "Sudden spikes of high activity",
            TemporalPattern.BURSTY_THEN_IDLE: "Initial burst followed by quiet period",
            TemporalPattern.IDLE_THEN_BURSTY: "Quiet period followed by burst",
            TemporalPattern.PERIODIC: "Regular intervals of activity",
            TemporalPattern.ESCALATING: "Increasing frequency over time",
            TemporalPattern.DECLINING: "Decreasing frequency over time",
            TemporalPattern.RANDOM: "No discernible pattern",
        }
        
        # Compute red flags
        red_flags = []
        if chunk.activity_profile.auth_failure_count > 10:
            red_flags.append(f"High auth failures: {chunk.activity_profile.auth_failure_count}")
        if chunk.activity_profile.failure_rate > 0.5:
            red_flags.append(f"High failure rate: {chunk.activity_profile.failure_rate:.0%}")
        if chunk.targets.unique_target_count > 5:
            red_flags.append(f"Multiple targets: {chunk.targets.unique_target_count} hosts")
        if 22 in chunk.ports or 3389 in chunk.ports:
            if chunk.activity_profile.deny_count > 5:
                red_flags.append("Blocked remote access attempts")
        
        return cls(
            chunk_id=chunk.chunk_id,
            time_window_str=time_str,
            duration_minutes=chunk.time_window.duration_minutes,
            actor=actor,
            activity_profile=activity,
            ports=chunk.ports,
            port_descriptions=port_descs,
            temporal_pattern=chunk.temporal_pattern.value,
            temporal_description=temporal_map.get(
                chunk.temporal_pattern, "Unknown pattern"
            ),
            context=chunk.context.model_dump(exclude_none=True),
            red_flags=red_flags,
        )
