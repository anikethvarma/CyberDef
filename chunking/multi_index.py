"""
Multi-Index Chunking Strategy

Single-pass chunking that builds multiple indices simultaneously.
Replaces the triple-pass approach for better performance at scale.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any
from uuid import UUID

from shared_models.events import NormalizedEvent
from shared_models.chunks import BehavioralChunk, ChunkStrategy
from chunking.strategies import (
    SrcIPChunkStrategy,
    DstHostChunkStrategy,
    UserChunkStrategy,
)
from core.logging import get_logger

logger = get_logger(__name__)


class MultiIndexChunkStrategy:
    """
    Multi-index chunking strategy that processes events once.
    
    Builds all grouping indices (src_ip, dst_host, user) in a single pass,
    then creates time-windowed chunks in parallel.
    """
    
    def __init__(
        self,
        src_ip_window_min: int = 20,   # 5-min buffer above 15-min log collection interval
        dst_host_window_min: int = 30,
        user_window_min: int = 120,
    ):
        self.strategies = {
            'src_ip': SrcIPChunkStrategy(window_minutes=src_ip_window_min),
            'dst_host': DstHostChunkStrategy(window_minutes=dst_host_window_min),
            'user': UserChunkStrategy(window_minutes=user_window_min),
        }
    
    async def chunk_events(
        self,
        events: list[NormalizedEvent],
        file_id: UUID,
    ) -> list[BehavioralChunk]:
        """
        Chunk events using src_ip as the sole primary grouping axis.

        Each unique source IP gets its own set of time-windowed chunks.
        dst_host and user data remain embedded inside every NormalizedEvent
        and are available to downstream consumers — creating separate chunks
        per destination would multiply chunk count by N destinations, causing
        the '9 events → 10 chunks' inflation bug.

        Args:
            events: List of normalized events
            file_id: Source file ID

        Returns:
            List of behavioral chunks, one per (src_ip, time-window) pair
        """
        if not events:
            return []

        logger.info(
            f"Chunking started | total_events={len(events)}, axis=src_ip"
        )

        # Sort once — _create_time_windows expects pre-sorted input
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # ── Single-axis grouping: src_ip only ────────────────────────────
        # dst_host and user strategies are INTENTIONALLY excluded here.
        # Running all three strategies produced N_dst_hosts + N_users extra chunks
        # for the same underlying events (triple-counting bug).
        src_ip_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in sorted_events:
            if event.src_ip:
                src_ip_groups[event.src_ip].append(event)

        logger.info(
            f"Grouping complete | unique_src_ips={len(src_ip_groups)}"
        )

        # ── Time-window chunking per source IP ───────────────────────────
        strategy = self.strategies['src_ip']
        chunks: list[BehavioralChunk] = []

        for group_key, group_events in src_ip_groups.items():
            window_chunks = strategy._create_time_windows(group_events, file_id)
            chunks.extend(window_chunks)
            logger.debug(
                f"src_ip={group_key} | events={len(group_events)}, chunks={len(window_chunks)}"
            )

        # Sort final output chronologically
        chunks.sort(key=lambda c: c.time_window.start)

        logger.info(
            f"Chunking complete | total_chunks={len(chunks)}, unique_src_ips={len(src_ip_groups)}"
        )

        return chunks
    
    def get_stats(self) -> dict[str, Any]:
        """Get chunking statistics."""
        return {
            "type": "multi_index",
            "strategies": list(self.strategies.keys()),
            "window_configs": {
                name: strat.window_minutes
                for name, strat in self.strategies.items()
            },
        }
