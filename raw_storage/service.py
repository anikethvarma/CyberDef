"""
Raw Storage Service

Provides immutable storage and retrieval of raw CSV files.
Ensures traceability from any output back to source data.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Optional
from uuid import UUID

import aiofiles
import aiofiles.os

from core.config import get_settings
from core.exceptions import StorageError
from core.logging import get_logger

logger = get_logger(__name__)


class RawStorageService:
    """
    Service for immutable storage of raw CSV files.
    
    Features:
    - Immutable storage (files are never modified)
    - Content-addressable retrieval
    - Integrity verification via checksum
    - Replay capability for reprocessing
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.storage_root = self.settings.raw_storage_dir
        self.storage_root.mkdir(parents=True, exist_ok=True)
    
    async def store(
        self,
        file_id: UUID,
        filename: str,
        content: bytes,
    ) -> tuple[Path, str]:
        """
        Store a file immutably.
        
        Args:
            file_id: Unique file identifier
            filename: Original filename
            content: File content
            
        Returns:
            Tuple of (storage_path, checksum)
        """
        # Compute checksum
        checksum = hashlib.sha256(content).hexdigest()
        
        # Create date-based directory structure
        date_path = datetime.utcnow().strftime("%Y/%m/%d")
        storage_dir = self.storage_root / date_path
        storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Sanitize filename
        safe_name = self._sanitize_filename(filename)
        storage_path = storage_dir / f"{file_id}_{safe_name}"
        
        # Check if file already exists (shouldn't happen with UUID)
        if storage_path.exists():
            existing_checksum = await self._compute_file_checksum(storage_path)
            if existing_checksum == checksum:
                logger.info(f"File already exists with same content | file_id={file_id}, path={storage_path}")
                return storage_path, checksum
            else:
                raise StorageError(
                    f"File exists with different content: {storage_path}",
                    path=str(storage_path),
                    operation="store",
                )
        
        # Write file
        async with aiofiles.open(storage_path, "wb") as f:
            await f.write(content)
        
        logger.info(f"File stored | file_id={file_id}, path={storage_path}, checksum={checksum[:16]}, size_bytes={len(content)}")
        
        return storage_path, checksum
    
    async def retrieve(self, file_id: UUID, storage_path: str) -> bytes:
        """
        Retrieve file content.
        
        Args:
            file_id: File identifier
            storage_path: Path where file is stored
            
        Returns:
            File content as bytes
        """
        path = Path(storage_path)
        
        if not path.exists():
            raise StorageError(
                f"File not found: {storage_path}",
                path=storage_path,
                operation="retrieve",
            )
        
        async with aiofiles.open(path, "rb") as f:
            content = await f.read()
        
        logger.debug(f"File retrieved | file_id={file_id}, path={storage_path}, size_bytes={len(content)}")
        
        return content
    
    async def verify_integrity(
        self,
        storage_path: str,
        expected_checksum: str,
    ) -> bool:
        """
        Verify file integrity using checksum.
        
        Args:
            storage_path: Path to file
            expected_checksum: Expected SHA256 checksum
            
        Returns:
            True if checksum matches
        """
        path = Path(storage_path)
        
        if not path.exists():
            logger.error(f"File not found for integrity check | path={storage_path}")
            return False
        
        actual_checksum = await self._compute_file_checksum(path)
        
        if actual_checksum != expected_checksum:
            logger.error(f"Integrity check failed | path={storage_path}, expected={expected_checksum[:16]}, actual={actual_checksum[:16]}")
            return False
        
        return True
    
    async def stream_file(
        self,
        storage_path: str,
        chunk_size: int = 8192,
    ) -> AsyncIterator[bytes]:
        """
        Stream file content in chunks.
        
        Args:
            storage_path: Path to file
            chunk_size: Size of each chunk
            
        Yields:
            Chunks of file content
        """
        path = Path(storage_path)
        
        if not path.exists():
            raise StorageError(
                f"File not found: {storage_path}",
                path=storage_path,
                operation="stream",
            )
        
        async with aiofiles.open(path, "rb") as f:
            while chunk := await f.read(chunk_size):
                yield chunk
    
    async def list_files(
        self,
        date: Optional[datetime] = None,
    ) -> list[Path]:
        """
        List stored files.
        
        Args:
            date: Optional date filter
            
        Returns:
            List of file paths
        """
        if date:
            date_path = date.strftime("%Y/%m/%d")
            search_dir = self.storage_root / date_path
            if not search_dir.exists():
                return []
            return list(search_dir.glob("*"))
        
        # Return all files
        return list(self.storage_root.rglob("*"))
    
    async def get_storage_stats(self) -> dict:
        """Get storage statistics."""
        total_files = 0
        total_size = 0
        
        for file_path in self.storage_root.rglob("*"):
            if file_path.is_file():
                total_files += 1
                total_size += file_path.stat().st_size
        
        return {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "storage_path": str(self.storage_root),
        }
    
    async def _compute_file_checksum(self, path: Path) -> str:
        """Compute SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        
        async with aiofiles.open(path, "rb") as f:
            while chunk := await f.read(8192):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage."""
        # Replace unsafe characters
        safe_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
        return "".join(c if c in safe_chars else "_" for c in filename)
