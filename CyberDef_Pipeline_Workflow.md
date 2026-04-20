# CyberDef Architectural Workflow & Log Trace

This document maps the exact sequence of how a raw log file moves through the CyberDef analysis pipeline down to the actual functions executed and the console log lines (`logger.info`) they produce.

---

### Step 1: Ingestion & Normalization
* **File:** `main.py`
* **Trigger:** Uploading a CSV or Syslog file to the API endpoint or File Watcher.
* **Flow:**
  1. The `ParserRegistry` detects the format (e.g., Apache, Linux Syslog) and slices strings into `ParsedEvent` dictionaries.
  2. `NormalizationService.normalize_batch_parallel()` catches the list and splits it across all your CPU cores for deep regex parsing (extracting clean IPs/ports). Automagically skips multi-processing if the file is tiny.
* **Console Output:** 
  >`INFO: Parallel normalization starting | file_id=... events=... workers=8`
  >`INFO: Parse & normalize complete | file_id=... events=148123`

### Step 2: Deterministic Rules Engine (Tier 1)
* **File:** `rules_engine/engine.py` 
* **Trigger:** Instantly following normalization.
* **Flow:**
  1. `DeterministicEngine.scan_parallel()` partitions the normalized events.
  2. All stateless signatures (e.g., SQL injections, specific bad ports) are executed by multi-core `_worker_pattern_scan()`.
  3. All stateful rate-based rules (e.g., failed logins per IP over a minute) group events in the main thread to ensure time-calculations are perfectly loss-less.
* **Console Output:**
  >`INFO: Parallel scan starting | events=148123 workers=8 ...`
  >`INFO: Tier 1 complete | threats=24 matches=432 time_ms=2904`

### Step 3: Correlation (Tier 2) & Incident Creation
* **File:** `main.py` -> `threat_state/correlator.py`
* **Trigger:** Tier 1 completion.
* **Flow:**
  1. Compares identified Tier 1 signatures with historic global threat events for cross-day correlation (`DayLevelCorrelator`).
  2. Any highly confident deterministic matches are instantly handed to `IncidentService.create_from_deterministic_threat()` to generate immediate dashboard tickets.
* **Console Output:**
  >`INFO: Tier 2 complete | total_findings=5 new_patterns=1`

### Step 4: Multi-Index Chunking
* **File:** `chunking/service.py` -> `chunking/multi_index.py`
* **Trigger:** Preparing complex, multi-event behavioral chunks for the AI.
* **Flow:**
  1. `ChunkingService.chunk_events()` uses `asyncio.gather` on `MultiIndexChunkStrategy` to build three behavioral grouping indexes simultaneously: Source IP (15-min windows), Destination Hosts (30-min windows), and Username (120-min windows).
* **Console Output:**
  >`INFO: Starting chunking | events=148123, strategy=multi_index`
  >`INFO: Index building complete | src_ip_groups=84 dst_host_groups=12...`
  >`INFO: Chunking complete | total_chunks=142`

### Step 5: Persistent Chunk Sharding & Auto-Cleanup
* **File:** `rollups/chunk_storage.py`
* **Trigger:** AI queue preparation. Only chunks deemed suspicious pass the `filter_suspicious_chunks` logic.
* **Flow:**
  1. Regardless of being sent to AI, all generated tracking chunks are passed to `ChunkStorage.store_chunks()`. 
  2. The chunks are dumped into a standalone JSON file labeled with your original log file's UUID.
  3. `cleanup_old_chunks()` automatically deletes any old JSON files that are exactly 30 days old to protect SSD storage integrity.
* **Console Output:**
  >`INFO: Suspicious chunk filtering | total_chunks=142, suspicious_chunks=16`
  >`INFO: Stored 142 chunks to disk | file_id=...`
  >`INFO: Auto-cleanup removed 3 expired chunk files`

### Step 6: Rollup Aggregation (Long-Horizon Check)
* **File:** `rollups/service.py`
* **Trigger:** Polling the `/api/v1/rollups` REST endpoint (typically via the frontend).
* **Flow:**
  1. The endpoint scans your hardware. If `cudf` acts as a driver to an NVIDIA GPU (e.g., your 24GB VRAM target server), it executes `create_rollup_gpu`.
  2. RAPIDS cuDF loads every single JSON shard from `Step 5` directly onto the Video RAM.
  3. It executes a GPU `groupby` mathematically aggregating `total_events` and `total_denials` across millions of IPs to detect "Low and Slow" attacks extending back nearly 30 full days.
  4. Yields a result flag showing `"gpu_accelerated": true`.
* **Console Output:**
  >`INFO: GPU rollup starting | files=104`
  >`INFO: GPU rollup complete | chunks=124039, files=104, actors=920, high_risk=4`
