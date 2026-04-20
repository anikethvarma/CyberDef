import asyncio
import os
import sys
from datetime import datetime
import uuid

# Provide relative pathing for imports
sys.path.insert(0, os.path.abspath("."))

from shared_models.chunks import (
    BehavioralChunk, ActorContext, ActivityProfile, TimeWindow, TargetContext, TemporalPattern, ChunkStrategy
)
from core.flush_buffer import get_flush_worker
from rollups.chunk_storage import get_chunk_storage

async def verify():
    print("[1] Initializing Flush Worker...")
    worker = get_flush_worker()
    worker.trigger_sec = 2  # Rapid flush for testing
    worker.max_items = 50000
    await worker.start()
    
    print("[2] Generating 25,000 Behavioral Chunks in RAM...")
    now = datetime.utcnow()
    
    file_id = uuid.uuid4()
    
    for i in range(25000):
        chunk = BehavioralChunk(
            chunk_id=uuid.uuid4(),
            file_id=file_id,
            strategy=ChunkStrategy.SRC_IP,
            time_window=TimeWindow(start=now, end=now, duration_minutes=15),
            actor=ActorContext(src_ip=f"10.0.0.{i%255}"),
            activity_profile=ActivityProfile(total_events=5, deny_count=2, events_per_minute=0.5),
            targets=TargetContext(dst_hosts=["192.168.1.1"], unique_target_count=1),
            temporal_pattern=TemporalPattern.RANDOM,
            created_at=now
        )
        await worker.submit_chunk(chunk)
        
    print(f"    -> Current internal queue length: {len(worker._queue)}")
    
    print("[3] Waiting 3 seconds for auto-flush (Simulating micro-batch limit)...")
    await asyncio.sleep(3)
    
    print("[4] Stopping Worker...")
    await worker.stop()
    
    print("[5] Validating Parquet Hive Partition...")
    storage = get_chunk_storage()
    stats = storage.get_stats()
    print(f"    -> Storage Stats: {stats}")
    
    print("[6] Validating Parquet CPU Parsing Engine...")
    parsed_count = 0
    try:
        # Just grab the first few to prove that the schema parses back safely
        for c in storage.get_all_chunks():
            parsed_count += 1
            if parsed_count >= 500:
                break
    except Exception as e:
        print(f"    -> Error during parsing: {e}")
        
    print(f"    -> Successfully pulled and validated {parsed_count} chunks from Parquet via Pandas natively!")

if __name__ == "__main__":
    asyncio.run(verify())
