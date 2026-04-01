"""
Event Models

Pydantic models for raw, parsed, and normalized network security events.
"""


from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field
import hashlib
import json


class EventAction(str, Enum):
    """Network event action types."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"
    REJECT = "REJECT"
    UNKNOWN = "UNKNOWN"


class NetworkProtocol(str, Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    RDP = "RDP"
    OTHER = "OTHER"


class RawEventRow(BaseModel):
    """
    Raw event row as read from CSV.
    Preserves original data for traceability.
    """
    file_id: UUID
    row_number: int
    raw_data: dict[str, Any]
    
    @computed_field
    @property
    def row_hash(self) -> str:
        """Generate deterministic hash of raw row data."""
        serialized = json.dumps(self.raw_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]


class ParsedEvent(BaseModel):
    """
    Event after device-specific parsing.
    Still contains vendor-specific fields before normalization.
    """
    file_id: UUID
    row_hash: str
    timestamp: Optional[datetime] = None
    source_address: Optional[str] = None
    destination_address: Optional[str] = None
    destination_hostname: Optional[str] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    application: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration_ms: Optional[int] = None
    raw_message: Optional[str] = None
    vendor_specific: dict[str, Any] = Field(default_factory=dict)
    parsed_data: Optional[dict[str, Any]] = None  # Extended fields for normalization
    parse_errors: list[str] = Field(default_factory=list)


class NormalizedEvent(BaseModel):
    """
    Normalized internal event schema.
    
    Production-ready schema with all fields needed for threat analysis.
    """
    event_id: UUID = Field(default_factory=uuid4)
    file_id: UUID
    row_hash: str
    timestamp: datetime
    
    # Core network fields
    src_ip: str
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    dst_host: Optional[str] = None
    
    # Action and protocol
    action: EventAction
    protocol: NetworkProtocol = NetworkProtocol.OTHER
    
    # Identity
    username: Optional[str] = None
    
    # Traffic metrics
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration_ms: Optional[int] = None
    
    # Application context
    application: Optional[str] = None
    
    # Internal/External classification
    is_internal_src: Optional[bool] = None
    is_internal_dst: Optional[bool] = None
    
    # ========== SECURITY ENRICHMENT FIELDS ==========
    
    # Severity and priority
    severity: Optional[str] = None  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: Optional[int] = None  # 0-100
    
    # Session tracking
    session_id: Optional[str] = None
    connection_id: Optional[str] = None
    
    # Threat intelligence
    threat_intel_match: Optional[str] = None  # IOC match from threat feeds
    threat_category: Optional[str] = None  # malware, phishing, c2, etc.
    
    # ========== ENDPOINT DATA FIELDS ==========
    
    # Process information (for endpoint logs)
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    process_path: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    
    # File operations
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None  # MD5, SHA1, or SHA256
    file_size: Optional[int] = None
    
    # Registry operations (Windows)
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    
    # ========== HTTP/WEB APPLICATION FIELDS ==========
    
    # HTTP metadata
    http_method: Optional[str] = None  # GET, POST, PUT, DELETE, etc.
    http_status: Optional[int] = None  # 200, 404, 500, etc.
    http_version: Optional[str] = None  # HTTP/1.1, HTTP/2
    uri_path: Optional[str] = None
    uri_query: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    content_type: Optional[str] = None
    
    # Request/Response data
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    
    # ========== EMAIL FIELDS ==========
    
    email_from: Optional[str] = None
    email_to: Optional[list[str]] = None
    email_subject: Optional[str] = None
    attachment_names: Optional[list[str]] = None
    
    # ========== DNS FIELDS ==========
    
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None  # A, AAAA, MX, TXT, etc.
    dns_response: Optional[list[str]] = None
    
    # ========== METADATA ==========
    
    # Original log fields for forensics
    original_message: Optional[str] = None
    vendor_specific: Optional[dict[str, Any]] = None
    
    # Enrichment flags
    enriched: bool = False
    enrichment_source: Optional[str] = None
    
    model_config = ConfigDict()


class EventBatch(BaseModel):
    """Batch of normalized events for processing."""
    batch_id: UUID = Field(default_factory=uuid4)
    file_id: UUID
    events: list[NormalizedEvent]
    total_rows_processed: int
    parse_error_count: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @property
    def success_rate(self) -> float:
        """Calculate parsing success rate."""
        if self.total_rows_processed == 0:
            return 0.0
        return (self.total_rows_processed - self.parse_error_count) / self.total_rows_processed
