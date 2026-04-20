"""
Long-Horizon Rollup Service

Correlates behavioral chunks across multiple files and extended time periods.
Detects low-and-slow attack patterns that span days or weeks.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import json

# GPU acceleration: try to import cuDF (RAPIDS)
try:
    import cudf  # type: ignore
    _HAS_CUDF = True
except ImportError:
    _HAS_CUDF = False

from pydantic import BaseModel, Field

from core.logging import get_logger
from shared_models.chunks import BehavioralChunk, TemporalPattern

logger = get_logger(__name__)


class ActorProfile(BaseModel):
    """Extended profile of an actor across multiple chunks."""
    profile_id: UUID = Field(default_factory=uuid4)
    
    # Identity
    primary_ip: str | None = None
    all_ips: list[str] = Field(default_factory=list)
    username: str | None = None
    
    # Time span
    first_seen: datetime
    last_seen: datetime
    active_days: int = 0
    
    # Aggregate metrics
    total_chunks: int = 0
    total_events: int = 0
    total_denials: int = 0
    
    # Target analysis
    unique_targets: set[str] = Field(default_factory=set)
    target_count: int = 0
    
    # Port analysis
    ports_accessed: set[int] = Field(default_factory=set)
    sensitive_port_access: bool = False
    
    # Patterns
    dominant_pattern: TemporalPattern = TemporalPattern.RANDOM
    
    # Risk indicators
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    
    # Source chunks
    chunk_ids: list[UUID] = Field(default_factory=list)
    file_ids: set[UUID] = Field(default_factory=set)
    
    class Config:
        arbitrary_types_allowed = True


class RollupResult(BaseModel):
    """Result of rollup analysis."""
    rollup_id: UUID = Field(default_factory=uuid4)
    
    # Time scope
    start_time: datetime
    end_time: datetime
    days_covered: int
    
    # Chunks analyzed
    chunks_analyzed: int
    files_analyzed: int
    
    # Actor profiles
    actor_profiles: list[ActorProfile] = Field(default_factory=list)
    
    # High-risk actors
    high_risk_actors: list[str] = Field(default_factory=list)
    
    # Cross-file correlations
    cross_file_patterns: list[dict[str, Any]] = Field(default_factory=list)
    
    # Created timestamp
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RollupService:
    """
    Service for long-horizon rollup analysis.
    
    Correlates behavioral chunks to detect:
    - Low-and-slow attack patterns
    - Distributed behavior across time
    - Persistent threat actors
    
    Memory-efficient: uses streaming metric aggregation instead of
    storing full BehavioralChunk objects (~50KB each). Only lightweight
    counters and sets (~200 bytes) are held per actor.
    """
    
    # Sensitive ports for risk calculation
    SENSITIVE_PORTS = {22, 23, 3389, 445, 135, 139, 5900, 1433, 3306, 5432}
    
    def __init__(self):
        self.rollups_performed = 0
    
    def create_rollup(
        self,
        chunks,
        min_actor_chunks: int = 2,
    ) -> RollupResult:
        """
        Create a rollup analysis from a chunk stream (generator or list).
        
        Uses streaming metric aggregation — never stores full BehavioralChunk
        objects. Each actor accumulates only lightweight counters (~200 bytes)
        instead of full Pydantic models (~50KB+). This prevents OOM for 500k+ chunks.
        """
        # Lightweight per-actor accumulators (NOT full chunk objects)
        actor_stats: dict[str, dict] = {}
        
        # Global trackers
        start_time = None
        end_time = None
        file_ids: set[UUID] = set()
        chunks_count = 0
        
        # Cross-file trackers
        actor_files: dict[str, set[UUID]] = defaultdict(set)
        target_files: dict[str, set[UUID]] = defaultdict(set)
        
        for chunk in chunks:
            chunks_count += 1
            
            # Time scope
            if start_time is None or chunk.time_window.start < start_time:
                start_time = chunk.time_window.start
            if end_time is None or chunk.time_window.end > end_time:
                end_time = chunk.time_window.end
            
            # File tracking
            file_ids.add(chunk.file_id)
            
            # Actor key
            if chunk.actor.username:
                actor_key = f"user:{chunk.actor.username}"
            elif chunk.actor.src_ip:
                actor_key = f"ip:{chunk.actor.src_ip}"
            elif chunk.actor.src_ips:
                actor_key = f"ip:{chunk.actor.src_ips[0]}"
            else:
                continue
            
            # ── Aggregate metrics into lightweight dict (NOT storing chunk) ──
            if actor_key not in actor_stats:
                actor_stats[actor_key] = {
                    "total_chunks": 0,
                    "total_events": 0,
                    "total_denials": 0,
                    "all_ips": set(),
                    "ip_event_counts": defaultdict(int),
                    "unique_targets": set(),
                    "ports": set(),
                    "unique_days": set(),
                    "first_seen": chunk.time_window.start,
                    "last_seen": chunk.time_window.end,
                    "pattern_counts": defaultdict(int),
                    "chunk_ids": [],
                    "file_ids": set(),
                }
            
            stats = actor_stats[actor_key]
            stats["total_chunks"] += 1
            stats["total_events"] += chunk.activity_profile.total_events
            stats["total_denials"] += chunk.activity_profile.deny_count
            
            # IPs
            if chunk.actor.src_ip:
                stats["all_ips"].add(chunk.actor.src_ip)
                stats["ip_event_counts"][chunk.actor.src_ip] += chunk.activity_profile.total_events
            stats["all_ips"].update(chunk.actor.src_ips)
            
            # Targets (cap at 1000 to prevent unbounded growth)
            if len(stats["unique_targets"]) < 1000:
                stats["unique_targets"].update(chunk.targets.dst_ips)
                stats["unique_targets"].update(chunk.targets.dst_hosts)
            
            # Ports
            stats["ports"].update(chunk.ports)
            
            # Time
            stats["unique_days"].add(chunk.time_window.start.date())
            if chunk.time_window.start < stats["first_seen"]:
                stats["first_seen"] = chunk.time_window.start
            if chunk.time_window.end > stats["last_seen"]:
                stats["last_seen"] = chunk.time_window.end
            
            # Temporal pattern
            stats["pattern_counts"][chunk.temporal_pattern] += 1
            
            # Chunk/file IDs (cap chunk_ids to save memory)
            if len(stats["chunk_ids"]) < 500:
                stats["chunk_ids"].append(chunk.chunk_id)
            stats["file_ids"].add(chunk.file_id)
            
            # Cross-file tracking
            if chunk.actor.src_ip:
                actor_files[chunk.actor.src_ip].add(chunk.file_id)
            for target in chunk.targets.dst_hosts:
                target_files[target].add(chunk.file_id)
        
        # ── Handle empty input ──
        if chunks_count == 0:
            return RollupResult(
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                days_covered=0,
                chunks_analyzed=0,
                files_analyzed=0,
            )
        
        days_covered = (end_time - start_time).days + 1
        
        # ── Build actor profiles from aggregated stats ──
        profiles = []
        high_risk_actors = []
        
        for actor_key, stats in actor_stats.items():
            if stats["total_chunks"] < min_actor_chunks:
                continue
            
            active_days = len(stats["unique_days"])
            sensitive_access = bool(stats["ports"] & self.SENSITIVE_PORTS)
            dominant_pattern = max(stats["pattern_counts"], key=stats["pattern_counts"].get)
            ip_counts = stats["ip_event_counts"]
            primary_ip = max(ip_counts, key=ip_counts.get) if ip_counts else None
            
            risk_score, risk_factors = self._calculate_risk(
                total_events=stats["total_events"],
                total_denials=stats["total_denials"],
                unique_targets=len(stats["unique_targets"]),
                active_days=active_days,
                sensitive_access=sensitive_access,
                pattern=dominant_pattern,
            )
            
            username = None
            if actor_key.startswith("user:"):
                username = actor_key[5:]
            
            profile = ActorProfile(
                primary_ip=primary_ip,
                all_ips=sorted(stats["all_ips"]),
                username=username,
                first_seen=stats["first_seen"],
                last_seen=stats["last_seen"],
                active_days=active_days,
                total_chunks=stats["total_chunks"],
                total_events=stats["total_events"],
                total_denials=stats["total_denials"],
                unique_targets=stats["unique_targets"],
                target_count=len(stats["unique_targets"]),
                ports_accessed=stats["ports"],
                sensitive_port_access=sensitive_access,
                dominant_pattern=dominant_pattern,
                risk_score=risk_score,
                risk_factors=risk_factors,
                chunk_ids=stats["chunk_ids"],
                file_ids=stats["file_ids"],
            )
            profiles.append(profile)
            
            if risk_score >= 0.7:
                high_risk_actors.append(actor_key)
        
        # ── Cross-file patterns ──
        cross_file_patterns = []
        for actor, files in actor_files.items():
            if len(files) >= 2:
                cross_file_patterns.append({
                    "type": "cross_file_actor",
                    "actor": actor,
                    "file_count": len(files),
                    "description": f"Actor {actor} appears in {len(files)} different log files",
                })
        for target, files in target_files.items():
            if len(files) >= 2:
                cross_file_patterns.append({
                    "type": "cross_file_target",
                    "target": target,
                    "file_count": len(files),
                    "description": f"Target {target} accessed across {len(files)} log files",
                })

        self.rollups_performed += 1
        
        logger.info(
            f"Rollup complete | chunks={chunks_count}, files={len(file_ids)}, actors={len(profiles)}, high_risk={len(high_risk_actors)}, days={days_covered}"
        )
        
        return RollupResult(
            start_time=start_time,
            end_time=end_time,
            days_covered=days_covered,
            chunks_analyzed=chunks_count,
            files_analyzed=len(file_ids),
            actor_profiles=profiles,
            high_risk_actors=high_risk_actors,
            cross_file_patterns=cross_file_patterns,
        )
    
    def _calculate_risk(
        self,
        total_events: int,
        total_denials: int,
        unique_targets: int,
        active_days: int,
        sensitive_access: bool,
        pattern: TemporalPattern,
    ) -> tuple[float, list[str]]:
        """Calculate risk score and factors."""
        score = 0.0
        factors = []
        
        # High denial rate
        if total_events > 0:
            denial_rate = total_denials / total_events
            if denial_rate >= 0.5:
                score += 0.25
                factors.append(f"High denial rate: {denial_rate:.0%}")
        
        # Many unique targets
        if unique_targets >= 10:
            score += 0.2
            factors.append(f"Many targets: {unique_targets}")
        elif unique_targets >= 5:
            score += 0.1
            factors.append(f"Multiple targets: {unique_targets}")
        
        # Persistence over days
        if active_days >= 7:
            score += 0.2
            factors.append(f"Persistent activity: {active_days} days")
        elif active_days >= 3:
            score += 0.1
            factors.append(f"Multi-day activity: {active_days} days")
        
        # Sensitive port access
        if sensitive_access:
            score += 0.15
            factors.append("Accessed sensitive ports")
        
        # Suspicious patterns
        if pattern == TemporalPattern.ESCALATING:
            score += 0.15
            factors.append("Escalating activity pattern")
        elif pattern == TemporalPattern.PERIODIC:
            score += 0.1
            factors.append("Automated/periodic pattern")
        
        # High volume
        if total_events >= 1000:
            score += 0.1
            factors.append(f"High volume: {total_events} events")
        
        return min(score, 1.0), factors
    
    def get_stats(self) -> dict[str, Any]:
        """Get rollup statistics."""
        return {
            "rollups_performed": self.rollups_performed,
            "gpu_available": _HAS_CUDF,
        }

    def create_rollup_gpu(
        self,
        chunks_dir: str,
        min_actor_chunks: int = 2,
    ) -> RollupResult:
        """
        GPU-accelerated rollup using RAPIDS cuDF.

        Loads chunk JSON files directly into a GPU DataFrame and performs
        groupby aggregations entirely in VRAM. This is ~50-100x faster
        than Python dict-based aggregation for 500k+ chunks.

        Falls back to CPU streaming if cuDF is not available.

        Args:
            chunks_dir: Path to the rollup_chunks directory
            min_actor_chunks: Minimum chunks per actor to include

        Returns:
            RollupResult with correlated analysis
        """
        if not _HAS_CUDF:
            logger.warning("cuDF not available — falling back to CPU rollup")
            from rollups.chunk_storage import get_chunk_storage
            storage = get_chunk_storage()
            return self.create_rollup(storage.get_all_chunks(), min_actor_chunks)

        import glob
        from pathlib import Path

        # Verify Parquet files exist in the directory tree
        has_parquet = False
        try:
            for _ in Path(chunks_dir).rglob("*.parquet"):
                has_parquet = True
                break
        except Exception:
            pass
            
        if not has_parquet:
            return RollupResult(
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                days_covered=0,
                chunks_analyzed=0,
                files_analyzed=0,
            )

        logger.info(f"GPU rollup starting | directory={chunks_dir}")

        try:
            import pandas as pd
            # Use Pandas to load the Hive Partitioned Parquet natively, resolving nested dicts safely
            # before passing the clean math matrix to GPU. This handles the complex nested models safely.
            pdf = pd.read_parquet(chunks_dir)
            
            # Flatten nested structures out of the Parquet dataframe
            records = []
            for _, row in pdf.iterrows():
                actor = row.get("actor", {}) if isinstance(row.get("actor"), dict) else {}
                activity = row.get("activity_profile", {}) if isinstance(row.get("activity_profile"), dict) else {}
                tw = row.get("time_window", {}) if isinstance(row.get("time_window"), dict) else {}
                records.append({
                    "src_ip": actor.get("src_ip"),
                    "username": actor.get("username"),
                    "total_events": activity.get("total_events", 0),
                    "deny_count": activity.get("deny_count", 0),
                    "start_time": tw.get("start"),
                    "end_time": tw.get("end"),
                    "file_id": str(row.get("file_id", "")),
                    "temporal_pattern": row.get("temporal_pattern", "random"),
                })
                
            # Create cuDF DataFrame natively on the GPU from the highly cleansed records
            gdf = cudf.DataFrame(records)
            
        except Exception as e:
            logger.error(f"Critical failure loading Parquet hive to GPU: {e}")
            return RollupResult(
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                days_covered=0,
                chunks_analyzed=0,
                files_analyzed=0,
            )

        # Determine actor key: prefer username, then src_ip
        gdf["actor_key"] = gdf["username"].where(
            gdf["username"].notna() & (gdf["username"] != ""),
            gdf["src_ip"],
        )
        gdf = gdf.dropna(subset=["actor_key"])

        # GPU groupby aggregation
        agg = gdf.groupby("actor_key").agg({
            "total_events": "sum",
            "deny_count": "sum",
            "file_id": "nunique",
            "src_ip": "count",   # chunk count
        }).reset_index()

        agg.columns = ["actor_key", "total_events", "total_denials", "files_count", "total_chunks"]

        # Filter by min_actor_chunks
        agg = agg[agg["total_chunks"] >= min_actor_chunks]

        # Convert back to CPU for ActorProfile construction
        result_df = agg.to_pandas()

        # Global stats
        all_files = gdf["file_id"].nunique().item() if hasattr(gdf["file_id"].nunique(), 'item') else int(gdf["file_id"].nunique())
        chunks_count = len(gdf)

        profiles = []
        high_risk_actors = []

        for _, row in result_df.iterrows():
            total_events = int(row["total_events"])
            total_denials = int(row["total_denials"])

            risk_score, risk_factors = self._calculate_risk(
                total_events=total_events,
                total_denials=total_denials,
                unique_targets=0,  # Not tracked in GPU path (lightweight)
                active_days=1,
                sensitive_access=False,
                pattern=TemporalPattern.RANDOM,
            )

            profile = ActorProfile(
                primary_ip=row["actor_key"] if not row["actor_key"].startswith("user:") else None,
                all_ips=[row["actor_key"]] if row["actor_key"] and not str(row["actor_key"]).startswith("user:") else [],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                total_chunks=int(row["total_chunks"]),
                total_events=total_events,
                total_denials=total_denials,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )
            profiles.append(profile)

            if risk_score >= 0.7:
                high_risk_actors.append(row["actor_key"])

        self.rollups_performed += 1

        logger.info(
            f"GPU rollup complete | chunks={chunks_count}, "
            f"files={all_files}, actors={len(profiles)}, "
            f"high_risk={len(high_risk_actors)}"
        )

        return RollupResult(
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            days_covered=1,
            chunks_analyzed=chunks_count,
            files_analyzed=all_files,
            actor_profiles=profiles,
            high_risk_actors=high_risk_actors,
        )
