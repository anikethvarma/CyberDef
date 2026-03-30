"""
Agent Models

Pydantic models for AI agent inputs and outputs.
All agent outputs are strict JSON with confidence scores.
"""


from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class KillChainStage(str, Enum):
    """Cyber kill chain stages."""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"
    # MITRE-aligned stages
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class IncidentPriority(str, Enum):
    """Incident priority levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class BaseAgentOutput(BaseModel):
    """Base class for all agent outputs."""
    output_id: UUID = Field(default_factory=uuid4)
    chunk_id: UUID  # Link to source chunk
    agent_name: str
    model_used: str = "llama3.1:latest"
    temperature: float = Field(ge=0.0, le=0.2)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    processing_time_ms: int = 0
    
    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v: float) -> float:
        if v > 0.2:
            raise ValueError("Temperature must be <= 0.2 for deterministic outputs")
        return v


class BehavioralInterpretation(BaseAgentOutput):
    """
    Output from Behavioral Interpretation Agent.
    Answers: Is this behavior meaningful or suspicious on its own?
    """
    agent_name: str = "behavioral_interpretation"
    
    interpretation: str = Field(
        ...,
        description="Human-readable interpretation of the behavior"
    )
    is_suspicious: bool = Field(
        ...,
        description="Whether the behavior warrants further investigation"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0 and 1"
    )
    reasoning: str = Field(
        default="",
        description="Brief explanation of the reasoning"
    )
    
    # Evidence references
    key_indicators: list[str] = Field(
        default_factory=list,
        description="Specific indicators that led to this interpretation"
    )


class ThreatIntent(BaseAgentOutput):
    """
    Output from Threat Intent Agent.
    Answers: What might the attacker be trying to accomplish?
    """
    agent_name: str = "threat_intent"
    
    suspected_intent: str = Field(
        ...,
        description="Suspected attacker intent"
    )
    kill_chain_stage: KillChainStage = Field(
        ...,
        description="Mapped kill chain / MITRE ATT&CK tactic"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0
    )
    alternative_intents: list[str] = Field(
        default_factory=list,
        description="Other possible intents considered"
    )
    reasoning: str = Field(
        default="",
        description="Explanation of intent inference"
    )


class MitreMapping(BaseAgentOutput):
    """
    Output from MITRE Reasoning Agent.
    Maps behavior to MITRE ATT&CK techniques.
    """
    agent_name: str = "mitre_mapping"
    
    technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="MITRE ATT&CK technique ID (e.g., T1110, T1110.001)"
    )
    technique_name: str = Field(
        ...,
        description="Human-readable technique name"
    )
    tactic: str = Field(
        ...,
        description="Parent tactic (e.g., Credential Access)"
    )
    justification: str = Field(
        ...,
        description="Why this technique was selected"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0
    )
    
    # Secondary mappings
    related_techniques: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Other potentially related techniques"
    )


class TriageResult(BaseAgentOutput):
    """
    Output from Triage & Narrative Agent.
    Provides priority and actionable recommendations.
    """
    agent_name: str = "triage"
    
    priority: IncidentPriority = Field(
        ...,
        description="Recommended incident priority"
    )
    risk_reason: str = Field(
        ...,
        description="Concise explanation of the risk"
    )
    recommended_action: str = Field(
        ...,
        description="Recommended next step for analyst"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0
    )
    
    # Narrative elements
    executive_summary: str = Field(
        default="",
        description="One-sentence summary for executives"
    )
    technical_summary: str = Field(
        default="",
        description="Technical summary for SOC analysts"
    )
    
    # Enrichment suggestions
    enrichment_suggestions: list[str] = Field(
        default_factory=list,
        description="Suggested data sources for further investigation"
    )

    # Structured incident mapping fields requested by UI
    raw_log: Optional[str] = Field(default=None, description="Representative raw log line")
    source_ip: Optional[str] = Field(default=None, description="Source IP")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP/host")
    suspicious: bool = Field(default=True, description="Whether behavior is suspicious")
    suspicious_indicator: str = Field(default="null", description="url|referer|user_agent|payload|source ip|null")
    attack_name: Optional[str] = Field(default=None, description="Attack or pattern name")
    brief_description: Optional[str] = Field(default=None, description="Short analyst-readable description")
    recommended_action_short: Optional[str] = Field(default=None, description="Primary response action")
    confidence_score: int = Field(default=1, ge=1, le=10, description="Confidence score from 1 to 10")
    mitre_tactic: Optional[str] = Field(default=None, description="MITRE ATT&CK tactic")
    mitre_technique: Optional[str] = Field(default=None, description="MITRE technique ID")


class AgentOutput(BaseModel):
    """
    Combined output from all agents for a single chunk.
    This is the complete analysis result.
    """
    analysis_id: UUID = Field(default_factory=uuid4)
    chunk_id: UUID
    
    # Individual agent outputs
    behavioral: Optional[BehavioralInterpretation] = None
    intent: Optional[ThreatIntent] = None
    mitre: Optional[MitreMapping] = None
    triage: Optional[TriageResult] = None
    
    # Overall assessment
    overall_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Average confidence across all agents"
    )
    requires_human_review: bool = Field(
        default=True,
        description="Whether human analyst review is required"
    )
    
    # Metadata
    total_processing_time_ms: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    def compute_overall_confidence(self) -> float:
        """Compute average confidence from all agent outputs."""
        confidences = []
        if self.behavioral:
            confidences.append(self.behavioral.confidence)
        if self.intent:
            confidences.append(self.intent.confidence)
        if self.mitre:
            confidences.append(self.mitre.confidence)
        if self.triage:
            confidences.append(self.triage.confidence)
        
        if not confidences:
            return 0.0
        
        self.overall_confidence = sum(confidences) / len(confidences)
        return self.overall_confidence


class AgentError(BaseModel):
    """Error from agent processing."""
    chunk_id: UUID
    agent_name: str
    error_type: str
    error_message: str
    raw_output: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
