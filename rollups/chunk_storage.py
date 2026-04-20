"""
Chunk Storage for Rollup Analysis

Stores behavioral chunks across files for long-horizon rollup analysis.
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

import pyarrow as pa
import pyarrow.parquet as pq

from core.config import get_settings
from core.logging import get_logger
from shared_models.chunks import BehavioralChunk

logger = get_logger(__name__)


def _get_chunks_dir() -> Path:
    """Get the chunks storage directory."""
    settings = get_settings()
    chunks_dir = settings.processed_dir / "rollup_chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    return chunks_dir


class ChunkStorage:
    """
    Storage for behavioral chunks for rollup analysis.
    
    Stores chunks from all analyzed files to enable
    cross-file correlation and long-horizon analysis.
    """
    
    def __init__(self):
        self.chunks_dir = _get_chunks_dir()
    
    def store_chunks(self, file_id: str, chunks: list[BehavioralChunk]) -> None:
        """
        Store chunks using Parquet with Hive partitioning.
        Massively decreases file size and natively loads into GPU VRAM.
        """
        # Convert Pydantic models to dicts safely for Parquet strict typing
        chunk_data = []
        for chunk in chunks:
            data = chunk.model_dump(mode='json')
            # Parquet strictly rejects empty dictionaries without a defined struct schema
            data["port_traffic"] = json.dumps(data.get("port_traffic", {}))
            data["protocol_distribution"] = json.dumps(data.get("protocol_distribution", {}))
            data["action_distribution"] = json.dumps(data.get("action_distribution", {}))
            chunk_data.append(data)
        
        if not chunk_data:
            return
            
        # Create Hive partition path (year=YYYY/month=MM/day=DD/hour=HH)
        now = datetime.utcnow()
        partitioned_dir = (
            self.chunks_dir 
            / f"year={now.year}" 
            / f"month={now.month:02d}" 
            / f"day={now.day:02d}" 
            / f"hour={now.hour:02d}"
        )
        partitioned_dir.mkdir(parents=True, exist_ok=True)
        
        chunk_file = partitioned_dir / f"{file_id}_chunks.parquet"
        
        try:
            # Write via PyArrow (Columnar)
            table = pa.Table.from_pylist(chunk_data)
            pq.write_table(table, chunk_file)
            
            logger.info(f"Stored {len(chunks)} chunks to Parquet | partition={partitioned_dir.name} file_id={file_id}")
            
            # Auto-cleanup: Prevent unbounded disk growth by pruning files older than 30 days
            settings = get_settings()
            retention_days = getattr(settings, 'rollup_retention_days', 30)
            cleaned = self.cleanup_old_chunks(retention_days)
            if cleaned > 0:
                logger.info(f"Auto-cleanup removed {cleaned} expired chunk files")
                
        except Exception as e:
            logger.error(f"Failed to save Parquet chunks for {file_id}: {e}")
            
    def cleanup_old_chunks(self, retention_days: int) -> int:
        """
        Delete chunk parquet files older than the retention limit.
        """
        deleted_count = 0
        cutoff_time = time.time() - (retention_days * 86400)
        
        # Use rglob to search through all the nested hive partition folders
        for cf in self.chunks_dir.rglob("*.parquet"):
            try:
                if cf.stat().st_mtime < cutoff_time:
                    cf.unlink()
                    deleted_count += 1
            except Exception as e:
                logger.warning(f"Error checking/deleting old chunk file {cf.name}: {e}")
                
        return deleted_count
    
    def get_all_chunks(self) -> Generator[BehavioralChunk, None, None]:
        """
        Memory-efficient CPU generator fallback.
        Recursively finds Parquet files and yields chunks to avoid OOM.
        """
        chunk_files = list(self.chunks_dir.rglob("*.parquet"))
        logger.info(f"Starting CPU Parquet stream | files={len(chunk_files)}")
        
        for cf in chunk_files:
            try:
                table = pq.read_table(cf)
                chunks_data = table.to_pylist()
                
                for chunk_dict in chunks_data:
                    try:
                        # Reparse Parquet JSON strings back to dicts
                        if isinstance(chunk_dict.get("port_traffic"), str):
                            chunk_dict["port_traffic"] = json.loads(chunk_dict["port_traffic"])
                        if isinstance(chunk_dict.get("protocol_distribution"), str):
                            chunk_dict["protocol_distribution"] = json.loads(chunk_dict["protocol_distribution"])
                        if isinstance(chunk_dict.get("action_distribution"), str):
                            chunk_dict["action_distribution"] = json.loads(chunk_dict["action_distribution"])
                        
                        yield BehavioralChunk.model_validate(chunk_dict)
                    except Exception as e:
                        logger.warning(f"Skipping malformed chunk in {cf.name}: {e}")
                
                del chunks_data
                del table
            except Exception as e:
                logger.error(f"Failed to read Parquet file {cf.name}: {e}")
    
    def get_stats(self) -> dict[str, Any]:
        """Get storage statistics without loading everything."""
        chunk_files = list(self.chunks_dir.rglob("*.parquet"))
        return {
            "files_stored": len(chunk_files),
            "storage_path": str(self.chunks_dir),
            "format": "parquet/hive"
        }


# Global instance
_storage: ChunkStorage | None = None


def get_chunk_storage() -> ChunkStorage:
    """Get the global chunk storage instance."""
    global _storage
    if _storage is None:
        _storage = ChunkStorage()
    return _storage
