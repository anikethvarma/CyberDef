"""
Chunking Strategies

Defines different strategies for grouping events into behavioral chunks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import UUID

from shared_models.events import NormalizedEvent
from shared_models.chunks import (
    BehavioralChunk,
    ChunkStrategy,
    TimeWindow,
    ActorContext,
    TargetContext,
    ActivityProfile,
    EnvironmentContext,
    TemporalPattern,
)
from core.logging import get_logger

logger = get_logger(__name__)


class BaseChunkStrategy(ABC):
    """
    Abstract base class for chunking strategies.
    
    Each strategy defines how to group events by a specific entity.
    """
    
    name: str = "base"
    strategy_type: ChunkStrategy = ChunkStrategy.CUSTOM
    
    # Time window configuration
    min_window_minutes: int = 15
    max_window_minutes: int = 60
    default_window_minutes: int = 30
    
    def __init__(self, window_minutes: int | None = None):
        self.window_minutes = window_minutes or self.default_window_minutes
    
    @abstractmethod
    def get_group_key(self, event: NormalizedEvent) -> str | None:
        """
        Get the grouping key for an event.
        
        Args:
            event: Normalized event
            
        Returns:
            Group key string or None if event shouldn't be grouped
        """
        pass
    
    @abstractmethod
    def build_actor_context(self, events: list[NormalizedEvent]) -> ActorContext:
        """
        Build actor context from grouped events.
        
        Args:
            events: Events in the group
            
        Returns:
            ActorContext for the chunk
        """
        pass
    
    def chunk_events(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
    ) -> list[BehavioralChunk]:
        """
        Chunk events using this strategy.
        
        Args:
            events: List of normalized events
            file_id: Source file ID
            
        Returns:
            List of behavioral chunks
        """
        if not events:
            return []
        
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Group by key
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in sorted_events:
            key = self.get_group_key(event)
            if key:
                groups[key].append(event)
        
        # Create time-windowed chunks for each group
        chunks = []
        for group_key, group_events in groups.items():
            window_chunks = self._create_time_windows(group_events, file_id)
            chunks.extend(window_chunks)
        
        logger.info(
            f"Chunking complete | strategy={self.name}, total_events={len(events)}, groups={len(groups)}, chunks={len(chunks)}"
        )
        
        return chunks
    
    def _create_time_windows(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
    ) -> list[BehavioralChunk]:
        """
        Create time-windowed chunks from a group of events using a fixed grid.

        The window boundary advances by exactly window_delta on a fixed grid
        anchored to the first event's timestamp. This prevents the 'floating
        anchor' bug where each out-of-window event resets the window start to
        its own timestamp, fragmenting events that are only seconds apart across
        a boundary into separate isolated chunks.

        Fixed-grid behaviour example (window=15min):
            E1@12:00  E2@12:07  E3@12:14:59  E4@12:15:01
            Grid:  12:00 → 12:15 → 12:30 → ...
            → Chunk 1: [E1, E2, E3]   window 12:00–12:15
            → Chunk 2: [E4]           window 12:15–12:30
        """
        if not events:
            return []

        chunks: list[BehavioralChunk] = []
        window_delta = timedelta(minutes=self.window_minutes)

        # Sort by timestamp (callers may pass pre-sorted, but guard here for safety)
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # ── Fixed grid anchor ────────────────────────────────────────────
        # current_window_start is the LEFT edge of the current bucket.
        # current_window_end   is the RIGHT edge (exclusive).
        # Both advance by window_delta — they NEVER reset to an event timestamp.
        current_window_start = sorted_events[0].timestamp
        current_window_end   = current_window_start + window_delta
        current_window_events: list[NormalizedEvent] = []

        for event in sorted_events:
            if event.timestamp < current_window_end:
                # Event fits inside the current window — normal case
                current_window_events.append(event)
            else:
                # Flush the current window as a completed chunk
                if current_window_events:
                    chunks.append(self._build_chunk(
                        current_window_events,
                        file_id,
                        current_window_start,
                    ))

                # ── Advance the grid forward ─────────────────────────────
                # Use a while loop so we skip over any completely empty
                # windows (e.g. a 45-minute gap skips 3 × 15-min buckets).
                while event.timestamp >= current_window_end:
                    current_window_start = current_window_end
                    current_window_end   = current_window_start + window_delta

                # Start the new window with this event
                current_window_events = [event]

        # Flush the final (possibly only) window
        if current_window_events:
            chunks.append(self._build_chunk(
                current_window_events,
                file_id,
                current_window_start,
            ))

        return chunks
    
    def _build_chunk(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
        window_start: datetime,
    ) -> BehavioralChunk:
        """Build a behavioral chunk from events."""
        window_end = max(e.timestamp for e in events)
        
        # Build contexts
        actor = self.build_actor_context(events)
        targets = self._build_target_context(events)
        activity = self._build_activity_profile(events)
        
        # Extract ports
        ports = sorted(set(
            e.dst_port for e in events
            if e.dst_port is not None
        ))
        
        # Categorize ports
        port_categories = self._categorize_ports(ports)
        
        # Detect temporal pattern
        temporal_pattern = self._detect_temporal_pattern(events)
        
        # Build environment context
        environment = EnvironmentContext(
            environment=self._detect_environment(events),
        )
        
        return BehavioralChunk(
            file_id=file_id,
            strategy=self.strategy_type,
            time_window=TimeWindow.from_datetimes(window_start, window_end),
            actor=actor,
            targets=targets,
            activity_profile=activity,
            ports=ports[:20],  # Limit to top 20
            port_categories=port_categories,
            temporal_pattern=temporal_pattern,
            context=environment,
            source_event_ids=[e.event_id for e in events],
            events=events,  # Store for extended threat analysis
        )
    
    def _build_target_context(self, events: list[NormalizedEvent]) -> TargetContext:
        """Build target context from events."""
        dst_ips = set(e.dst_ip for e in events if e.dst_ip)
        dst_hosts = set(e.dst_host for e in events if e.dst_host)
        
        return TargetContext(
            dst_ips=sorted(dst_ips)[:20],
            dst_hosts=sorted(dst_hosts)[:20],
            unique_target_count=len(dst_ips | dst_hosts),
        )
    
    def _build_activity_profile(self, events: list[NormalizedEvent]) -> ActivityProfile:
        """Build activity profile from events."""
        from shared_models.events import EventAction
        
        total = len(events)
        allow_count = sum(1 for e in events if e.action == EventAction.ALLOW)
        deny_count = sum(1 for e in events if e.action == EventAction.DENY)
        
        # Count unique entities
        unique_src = len(set(e.src_ip for e in events))
        unique_dst_ip = len(set(e.dst_ip for e in events if e.dst_ip))
        unique_dst_host = len(set(e.dst_host for e in events if e.dst_host))
        unique_ports = len(set(e.dst_port for e in events if e.dst_port))
        
        # Traffic volume
        bytes_sent = sum(e.bytes_sent or 0 for e in events)
        bytes_recv = sum(e.bytes_received or 0 for e in events)
        
        # Calculate failure rate
        failure_rate = deny_count / total if total > 0 else 0
        
        # Calculate events per minute
        if len(events) >= 2:
            duration = (
                max(e.timestamp for e in events) -
                min(e.timestamp for e in events)
            ).total_seconds() / 60
            events_per_min = total / duration if duration > 0 else total
        else:
            events_per_min = float(total)
        
        return ActivityProfile(
            total_events=total,
            allow_count=allow_count,
            deny_count=deny_count,
            unique_src_ips=unique_src,
            unique_dst_ips=unique_dst_ip,
            unique_dst_hosts=unique_dst_host,
            unique_ports=unique_ports,
            total_bytes_sent=bytes_sent,
            total_bytes_received=bytes_recv,
            failure_rate=failure_rate,
            events_per_minute=events_per_min,
        )
    
    def _categorize_ports(self, ports: list[int]) -> list[str]:
        """Categorize ports by service."""
        port_map = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            5672: "AMQP",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
        }
        
        categories = []
        for port in ports[:10]:
            if port in port_map:
                categories.append(port_map[port])
        
        return list(set(categories))
    
    def _detect_temporal_pattern(
        self,
        events: list[NormalizedEvent],
    ) -> TemporalPattern:
        """Detect temporal pattern in event sequence."""
        if len(events) < 3:
            return TemporalPattern.RANDOM
        
        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(sorted_events)):
            delta = (
                sorted_events[i].timestamp -
                sorted_events[i-1].timestamp
            ).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return TemporalPattern.RANDOM
        
        avg_interval = sum(intervals) / len(intervals)
        
        # Check for patterns
        # Bursty: many events with small intervals
        small_intervals = sum(1 for i in intervals if i < 5)
        if small_intervals > len(intervals) * 0.7:
            # Check if burst is at start or end
            first_half = intervals[:len(intervals)//2]
            second_half = intervals[len(intervals)//2:]
            
            first_avg = sum(first_half) / len(first_half) if first_half else 0
            second_avg = sum(second_half) / len(second_half) if second_half else 0
            
            if first_avg < second_avg * 0.5:
                return TemporalPattern.BURSTY_THEN_IDLE
            elif second_avg < first_avg * 0.5:
                return TemporalPattern.IDLE_THEN_BURSTY
            else:
                return TemporalPattern.BURSTY
        
        # Steady: consistent intervals
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        cv = (variance ** 0.5) / avg_interval if avg_interval > 0 else 0
        
        if cv < 0.5:
            return TemporalPattern.STEADY
        
        # Check for periodic pattern
        if len(intervals) >= 5:
            # Simple periodicity check
            sorted_intervals = sorted(intervals)
            median = sorted_intervals[len(sorted_intervals) // 2]
            close_to_median = sum(
                1 for i in intervals
                if abs(i - median) < median * 0.3
            )
            if close_to_median > len(intervals) * 0.6:
                return TemporalPattern.PERIODIC
        
        # Check for escalating/declining
        if len(intervals) >= 4:
            first_third = intervals[:len(intervals)//3]
            last_third = intervals[-len(intervals)//3:]
            
            first_avg = sum(first_third) / len(first_third)
            last_avg = sum(last_third) / len(last_third)
            
            if last_avg < first_avg * 0.5:
                return TemporalPattern.ESCALATING
            elif first_avg < last_avg * 0.5:
                return TemporalPattern.DECLINING
        
        return TemporalPattern.RANDOM
    
    def _detect_environment(self, events: list[NormalizedEvent]) -> str | None:
        """Detect environment from events."""
        # Check for environment hints in hostnames
        for event in events:
            if event.dst_host:
                host_lower = event.dst_host.lower()
                if any(x in host_lower for x in ["prod", "production"]):
                    return "PROD"
                elif any(x in host_lower for x in ["stag", "staging", "stage"]):
                    return "STAGING"
                elif any(x in host_lower for x in ["dev", "development"]):
                    return "DEV"
                elif "test" in host_lower:
                    return "TEST"
        
        return None


class SrcIPChunkStrategy(BaseChunkStrategy):
    """Group events by source IP address."""
    
    name = "src_ip"
    strategy_type = ChunkStrategy.SRC_IP
    min_window_minutes = 15
    max_window_minutes = 30
    default_window_minutes = 15
    
    def get_group_key(self, event: NormalizedEvent) -> str | None:
        return event.src_ip
    
    def build_actor_context(self, events: list[NormalizedEvent]) -> ActorContext:
        src_ip = events[0].src_ip if events else None
        usernames = set(e.username for e in events if e.username)
        
        return ActorContext(
            src_ip=src_ip,
            username=list(usernames)[0] if len(usernames) == 1 else None,
            is_internal=events[0].is_internal_src if events else None,
        )


class DstHostChunkStrategy(BaseChunkStrategy):
    """Group events by destination host."""
    
    name = "dst_host"
    strategy_type = ChunkStrategy.DST_HOST
    min_window_minutes = 30
    max_window_minutes = 60
    default_window_minutes = 30
    
    def get_group_key(self, event: NormalizedEvent) -> str | None:
        return event.dst_host or event.dst_ip
    
    def build_actor_context(self, events: list[NormalizedEvent]) -> ActorContext:
        src_ips = sorted(set(e.src_ip for e in events))
        
        return ActorContext(
            src_ips=src_ips[:20],
            is_internal=all(e.is_internal_src for e in events if e.is_internal_src is not None),
        )


class UserChunkStrategy(BaseChunkStrategy):
    """Group events by username."""
    
    name = "user"
    strategy_type = ChunkStrategy.USER
    min_window_minutes = 60
    max_window_minutes = 240
    default_window_minutes = 120
    
    def get_group_key(self, event: NormalizedEvent) -> str | None:
        return event.username
    
    def build_actor_context(self, events: list[NormalizedEvent]) -> ActorContext:
        username = events[0].username if events else None
        src_ips = sorted(set(e.src_ip for e in events))
        
        return ActorContext(
            username=username,
            src_ips=src_ips[:20],
        )
