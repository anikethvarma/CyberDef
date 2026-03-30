"""
AegisNet Shared Models

Core Pydantic models used across all modules for type-safe data handling.
"""


from shared_models.events import (
    NormalizedEvent,
    RawEventRow,
    ParsedEvent,
    EventAction,
    NetworkProtocol,
)
from shared_models.chunks import (
    BehavioralChunk,
    ChunkSummary,
    TimeWindow,
    ActorContext,
    ActivityProfile,
    TemporalPattern,
)
from shared_models.agents import (
    BehavioralInterpretation,
    ThreatIntent,
    MitreMapping,
    TriageResult,
    AgentOutput,
)
from shared_models.files import (
    FileMetadata,
    FileSource,
    FileValidationResult,
    FileStatus,
)
from shared_models.incidents import (
    Incident,
    IncidentStatus,
    IncidentPriority,
)

__all__ = [
    # Events
    "NormalizedEvent",
    "RawEventRow",
    "ParsedEvent",
    "EventAction",
    "NetworkProtocol",
    # Chunks
    "BehavioralChunk",
    "ChunkSummary",
    "TimeWindow",
    "ActorContext",
    "ActivityProfile",
    "TemporalPattern",
    # Agents
    "BehavioralInterpretation",
    "ThreatIntent",
    "MitreMapping",
    "TriageResult",
    "AgentOutput",
    # Files
    "FileMetadata",
    "FileSource",
    "FileValidationResult",
    "FileStatus",
    # Incidents
    "Incident",
    "IncidentStatus",
    "IncidentPriority",
]
