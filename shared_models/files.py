"""
File Models

Pydantic models for file intake, validation, and metadata.
"""


from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class FileSource(str, Enum):
    """Source of the file intake."""
    MANUAL_UPLOAD = "manual"
    LOCAL_SCAN = "local_scan"
    API = "api"


class FileStatus(str, Enum):
    """Processing status of a file."""
    PENDING = "pending"
    VALIDATING = "validating"
    VALID = "valid"
    INVALID = "invalid"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


class FileValidationResult(BaseModel):
    """Result of file validation."""
    is_valid: bool
    file_size_bytes: int
    row_count: Optional[int] = None
    column_count: Optional[int] = None
    detected_encoding: str = "utf-8"
    detected_delimiter: str = ","
    has_header: bool = True
    validation_errors: list[str] = Field(default_factory=list)
    validation_warnings: list[str] = Field(default_factory=list)
    sample_columns: list[str] = Field(default_factory=list)


class FileMetadata(BaseModel):
    """
    Metadata for an ingested file.
    Stored after successful intake.
    """
    file_id: UUID = Field(default_factory=uuid4)
    
    # Source information
    original_filename: str
    source: FileSource
    source_path: Optional[str] = None  # For local scan
    
    # Storage
    storage_path: str  # Path in raw storage
    
    # Validation
    checksum_sha256: str
    file_size_bytes: int
    content_type: Optional[str] = "text/csv"  # MIME type
    description: Optional[str] = None  # Optional description
    
    # Content metadata
    row_count: Optional[int] = None
    column_count: Optional[int] = None
    columns: list[str] = Field(default_factory=list)
    
    # Parser hints
    detected_format: Optional[str] = None  # firewall, network_log, etc.
    detected_vendor: Optional[str] = None
    
    # Status tracking
    status: FileStatus = FileStatus.PENDING
    
    # Timestamps
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    validated_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    
    # Processing results
    events_created: int = 0
    parse_errors: int = 0
    
    # Analysis results
    chunks_created: int = 0
    suspicious_chunks_count: int = 0
    ai_analysis_count: int = 0
    incidents_created: int = 0
    
    model_config = ConfigDict()


class FileUploadRequest(BaseModel):
    """Request model for file upload."""
    filename: str
    content_type: str = "text/csv"
    description: Optional[str] = None
    tags: list[str] = Field(default_factory=list)


class FileUploadResponse(BaseModel):
    """Response model after successful file upload."""
    file_id: UUID
    source: FileSource
    checksum: str
    uploaded_at: datetime
    status: FileStatus
    message: str = "File uploaded successfully"


class DirectoryScanRequest(BaseModel):
    """Request model for directory scanning."""
    directory_path: str
    file_pattern: str = "*.csv"
    recursive: bool = False
    max_files: int = 100


class DirectoryScanResult(BaseModel):
    """Result of directory scan."""
    directory_path: str
    files_found: int
    files_processed: int
    files_skipped: int
    file_ids: list[UUID] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    scan_duration_ms: int = 0
