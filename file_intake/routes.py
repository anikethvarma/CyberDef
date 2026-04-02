"""
File Intake API Routes

FastAPI routes for file upload and directory scanning.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated
import re

from datetime import datetime

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status, Depends
from fastapi.responses import FileResponse

from core.config import get_settings
from core.logging import get_logger
from core.auth import require_auth, optional_auth
from shared_models.files import (
    FileMetadata,
    FileSource,
    FileStatus,
    FileUploadResponse,
    DirectoryScanRequest,
    DirectoryScanResult,
)
from file_intake.service import FileIntakeService

logger = get_logger(__name__)
router = APIRouter(prefix="/files", tags=["File Intake"])

# Service instance (in production, use dependency injection)
_service: FileIntakeService | None = None


def get_service() -> FileIntakeService:
    """Get or create file intake service."""
    global _service
    if _service is None:
        _service = FileIntakeService()
    return _service


def _find_report_path(file_id: str) -> Path | None:
    """Locate the latest report file for a given file_id."""
    reports_dir = Path(get_settings().base_dir) / "reports"
    if not reports_dir.exists():
        return None

    # Preferred: filename includes file_id (newer reports)
    candidates: list[Path] = []
    for pattern in (f"*_{file_id}_*_report.md", f"*{file_id}*_report.md", f"*{file_id}*.md"):
        candidates.extend([path for path in reports_dir.glob(pattern) if path.is_file()])
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)

    # Fallback: scan report headers for file_id (older reports)
    for report_path in sorted(
        reports_dir.glob("*.md"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if not report_path.is_file():
            continue
        try:
            with report_path.open("r", encoding="utf-8") as handle:
                for _ in range(60):
                    line = handle.readline()
                    if not line:
                        break
                    if file_id in line:
                        return report_path
        except Exception:
            continue

    return None


def _find_incident_json_path(file_id: str) -> Path | None:
    """Locate the latest incident JSON report for a given file_id."""
    reports_dir = Path(get_settings().base_dir) / "reports"
    if not reports_dir.exists():
        return None

    candidates = [
        path
        for path in reports_dir.glob(f"*_{file_id}_*_incidents.json")
        if path.is_file()
    ]
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_mtime)

    for report_path in sorted(
        reports_dir.glob("*_incidents.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if not report_path.is_file():
            continue
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            if str(payload.get("file_id", "")) == file_id:
                return report_path
        except Exception:
            continue

    return None


def _report_metadata(report_path: Path, file_id: str | None = None) -> dict:
    """Build serializable report metadata."""
    stat = report_path.stat()
    resolved_file_id = (
        file_id
        or _extract_file_id_from_report_name(report_path.name)
        or _extract_file_id_from_report_content(report_path)
    )
    return {
        "report_name": report_path.name,
        "report_path": str(report_path),
        "file_id": resolved_file_id,
        "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "size_bytes": stat.st_size,
    }


def _extract_file_id_from_report_name(filename: str) -> str | None:
    """Extract UUID-like file_id from report filename if available."""
    parts = filename.split("_")
    if len(parts) < 4:
        return None
    possible = parts[2]
    if len(possible) >= 32:
        return possible
    return None


def _extract_file_id_from_report_content(report_path: Path) -> str | None:
    """Best-effort extraction of file_id from report markdown body."""
    uuid_pattern = re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    )
    try:
        with report_path.open("r", encoding="utf-8") as handle:
            for _ in range(80):
                line = handle.readline()
                if not line:
                    break
                match = uuid_pattern.search(line)
                if match:
                    return match.group(0)
    except Exception:
        return None
    return None


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a CSV file",
    description="Upload a CSV file for analysis. The file will be validated, stored, and queued for processing.",
)
async def upload_file(
    file: Annotated[UploadFile, File(description="CSV file to upload")],
    description: Annotated[str | None, Form()] = None,
) -> FileUploadResponse:
    """Upload a CSV file for analysis."""
    service = get_service()
    
    # Validate content type
    if file.content_type and "csv" not in file.content_type.lower():
        if "text" not in file.content_type.lower():
            logger.warning(f"Unexpected content type | content_type={file.content_type}, filename={file.filename}")
    
    # Read content
    content = await file.read()
    
    try:
        response = await service.upload_file(
            filename=file.filename or "unknown.csv",
            content=content,
            source=FileSource.MANUAL_UPLOAD,
            description=description,
        )
        return response
    except Exception as e:
        logger.error(f"File upload failed | error={e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post(
    "/scan",
    response_model=DirectoryScanResult,
    summary="Scan a local directory",
    description="Scan a local directory for CSV files and import them.",
)
async def scan_directory(
    request: DirectoryScanRequest,
) -> DirectoryScanResult:
    """Scan a local directory for CSV files."""
    service = get_service()
    
    try:
        result = await service.scan_directory(request)
        return result
    except Exception as e:
        logger.error(f"Directory scan failed | error={e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/",
    response_model=list[FileMetadata],
    summary="List uploaded files",
    description="List all uploaded files with optional status filter.",
)
async def list_files(
    status: FileStatus | None = None,
    limit: int = 100,
) -> list[FileMetadata]:
    """List uploaded files."""
    service = get_service()
    return await service.list_files(status=status, limit=limit)


@router.get(
    "/reports",
    summary="List generated markdown reports",
    description="List markdown reports from the reports directory, optionally filtered by file_id.",
)
async def list_reports(file_id: str | None = None) -> list[dict]:
    """List generated markdown reports from the reports directory."""
    reports_dir = Path(get_settings().base_dir) / "reports"
    if not reports_dir.exists():
        return []

    report_candidates: dict[str, Path] = {}

    if file_id:
        for pattern in (f"*_{file_id}_*_report.md", f"*{file_id}*.md"):
            for path in reports_dir.glob(pattern):
                if path.is_file():
                    report_candidates[str(path)] = path
        if not report_candidates:
            for path in reports_dir.glob("*.md"):
                if not path.is_file():
                    continue
                extracted = _extract_file_id_from_report_name(path.name) or _extract_file_id_from_report_content(path)
                if extracted == file_id:
                    report_candidates[str(path)] = path
    else:
        for pattern in ("*_report.md", "*.md"):
            for path in reports_dir.glob(pattern):
                if path.is_file():
                    report_candidates[str(path)] = path

    candidates = list(report_candidates.values())
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [_report_metadata(path, file_id=file_id) for path in candidates]


@router.get(
    "/reports/",
    summary="List generated markdown reports (slash alias)",
    description="Alias for /files/reports.",
)
async def list_reports_slash_alias(file_id: str | None = None) -> list[dict]:
    """Alias endpoint to avoid route mismatches for trailing slash."""
    return await list_reports(file_id=file_id)


@router.get(
    "/{file_id}/report-content",
    summary="Get report markdown content",
    description="Return generated markdown report content for UI rendering.",
)
async def get_file_report_content(file_id: str) -> dict:
    """Get report content and metadata for a file."""
    report_path = _find_report_path(file_id)
    if not report_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found for file: {file_id}",
        )

    try:
        content = report_path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error(f"Failed reading report | file_id={file_id}, error={exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to read generated report content",
        ) from exc

    payload = _report_metadata(report_path, file_id=file_id)
    payload["content"] = content
    return payload


@router.get(
    "/{file_id}",
    response_model=FileMetadata,
    summary="Get file metadata",
    description="Get metadata for a specific file.",
)
async def get_file(file_id: str) -> FileMetadata:
    """Get file metadata by ID."""
    service = get_service()
    metadata = await service.get_file(file_id)
    
    if not metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )
    
    return metadata


@router.get(
    "/{file_id}/content",
    summary="Get file content",
    description="Get the raw content of a stored file.",
)
async def get_file_content(file_id: str) -> bytes:
    """Get raw file content."""
    service = get_service()
    
    content = await service.get_file_content(file_id)
    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )
    
    return content


@router.get(
    "/{file_id}/report",
    summary="Download analysis report",
    description="Download the generated analysis report for a processed file.",
)
async def get_file_report(file_id: str, download: bool = True) -> FileResponse:
    """Get analysis report as a downloadable or inline file."""
    report_path = _find_report_path(file_id)
    if not report_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report not found for file: {file_id}",
        )

    disposition = "attachment" if download else "inline"
    headers = {"Content-Disposition": f'{disposition}; filename="{report_path.name}"'}
    return FileResponse(
        path=str(report_path),
        media_type="text/markdown",
        filename=report_path.name,
        headers=headers,
    )


@router.get(
    "/{file_id}/incidents-json",
    summary="Download incident JSON report",
    description="Download machine-readable incident JSON report for a processed file.",
)
async def get_file_incidents_json(
    file_id: str, 
    download: bool = True,
    current_user: str = Depends(optional_auth),
) -> FileResponse:
    """
    Get incident JSON report as downloadable or inline file.
    
    Note: Authentication is optional for backend testing. If no token is provided,
    a default test user will be used.
    """
    report_path = _find_incident_json_path(file_id)
    if not report_path:
        # Backfill on-demand for older analyses where JSON report did not exist yet.
        try:
            from incidents.service import IncidentService
            from reports.writer import ReportWriter
            from core.auth import resolve_user_identity

            incident_service = IncidentService()
            incidents = incident_service.list_incidents_for_file(file_id)

            if incidents:
                file_service = get_service()
                metadata = await file_service.get_file(file_id)
                filename = (
                    metadata.original_filename
                    if metadata and metadata.original_filename
                    else f"{file_id}.csv"
                )
                
                # Extract emp_id from current user
                user_identity = resolve_user_identity(current_user)
                emp_id = user_identity.get("emp_id")
                
                writer = ReportWriter()
                report_path = writer.generate_incident_json_report(
                    file_id=file_id,
                    filename=filename,
                    incidents=incidents,
                    emp_id=emp_id,
                )
        except Exception as exc:
            logger.error(f"Failed to backfill incident JSON report | file_id={file_id}, error={exc}")

    if not report_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident JSON report not found for file: {file_id}",
        )

    disposition = "attachment" if download else "inline"
    headers = {"Content-Disposition": f'{disposition}; filename="{report_path.name}"'}
    return FileResponse(
        path=str(report_path),
        media_type="application/json",
        filename=report_path.name,
        headers=headers,
    )
