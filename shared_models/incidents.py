"""
Incident Models

Pydantic models for incident management and reporting.
"""


from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentPriority(str, Enum):
    """Incident priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IncidentSource(str, Enum):
    """How the incident was created."""
    AI_DETECTION = "ai_detection"
    DETERMINISTIC = "deterministic"
    MANUAL = "manual"
    CORRELATION = "correlation"


class MitreReference(BaseModel):
    """MITRE ATT&CK reference within an incident."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    justification: str


class IncidentTimeline(BaseModel):
    """Timeline entry for an incident."""
    timestamp: datetime
    event_type: str
    description: str
    actor: Optional[str] = None
    evidence_refs: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    """
    Security incident aggregating related agent outputs.
    """
    incident_id: UUID = Field(default_factory=uuid4)
    
    # Title and description
    title: str
    description: str
    
    # Classification
    status: IncidentStatus = IncidentStatus.NEW
    priority: IncidentPriority = IncidentPriority.MEDIUM
    source: IncidentSource = IncidentSource.AI_DETECTION
    
    # Time bounds
    first_seen: datetime
    last_seen: datetime
    
    # Related data
    chunk_ids: list[UUID] = Field(default_factory=list)
    agent_output_ids: list[UUID] = Field(default_factory=list)
    file_ids: list[UUID] = Field(default_factory=list)
    
    # Actor information
    primary_actor_ip: Optional[str] = None
    actor_ips: list[str] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    
    # MITRE mapping
    mitre_techniques: list[MitreReference] = Field(default_factory=list)
    primary_tactic: Optional[str] = None
    
    # Confidence
    overall_confidence: float = Field(ge=0.0, le=1.0)
    
    # Narratives
    executive_summary: str = ""
    technical_summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)

    # Analyst-mapped fields for UI/JSON export
    mi_id: str = Field(default="GenAI_SOC", alias="$MI_ID")
    raw_log: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    suspicious: bool = True
    suspicious_indicator: Optional[str] = None
    attack_name: Optional[str] = None
    brief_description: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence_score: int = Field(default=1, ge=1, le=10)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    # Timeline
    timeline: list[IncidentTimeline] = Field(default_factory=list)
    
    # Detection metadata
    detection_tier: Optional[str] = None  # "deterministic", "correlation", "ai_agent"
    detection_rule: Optional[str] = None  # Which rule/correlation triggered this
    
    # Assignment and tracking
    assigned_to: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    
    model_config = ConfigDict()


class IncidentCreateRequest(BaseModel):
    """Request to create a new incident."""
    title: str
    description: str
    priority: IncidentPriority = IncidentPriority.MEDIUM
    chunk_ids: list[UUID] = Field(default_factory=list)
    assigned_to: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class IncidentUpdateRequest(BaseModel):
    """Request to update an incident."""
    status: Optional[IncidentStatus] = None
    priority: Optional[IncidentPriority] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    tags: Optional[list[str]] = None


class IncidentSummary(BaseModel):
    """Brief summary for incident lists."""
    incident_id: UUID
    title: str
    status: IncidentStatus
    priority: IncidentPriority
    first_seen: datetime
    last_seen: datetime
    chunk_count: int
    confidence: float
    primary_tactic: Optional[str] = None
    file_ids: list[UUID] = Field(default_factory=list)
    raw_log: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    suspicious: bool = True
    suspicious_indicator: Optional[str] = None
    attack_name: Optional[str] = None
    brief_description: Optional[str] = None
    recommended_action: Optional[str] = None
    confidence_score: int = 1
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None



class IncidentReport(BaseModel):
    """Full incident report for analysts."""
    incident: Incident
    
    # Extended details
    behavioral_interpretations: list[dict] = Field(default_factory=list)
    threat_intents: list[dict] = Field(default_factory=list)
    mitre_mappings: list[dict] = Field(default_factory=list)
    
    # Traceability
    source_files: list[dict] = Field(default_factory=list)
    event_sample: list[dict] = Field(default_factory=list)
    
    # Generated at
    generated_at: datetime = Field(default_factory=datetime.utcnow)
