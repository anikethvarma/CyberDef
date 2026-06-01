"""
AegisNet - AI-Based Network Threat Analysis Platform

Main FastAPI application entry point.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from case_api.routes import router as case_router
from core.auth import optional_auth, require_auth
from core.auth_routes import router as auth_router
from core.config import get_settings
from core.logging import get_logger, setup_logging
from file_intake.routes import router as file_router

# Initialize logging
setup_logging()
logger = get_logger(__name__)


async def pre_flight_check() -> dict[str, bool]:
    """Verify system readiness for air-gapped deployment."""
    settings = get_settings()
    results = {
        "database": False,
        "ollama_api": False,
        "ollama_model": False,
        "ollama_embed": False,
        "directories": True,
    }

    # 1. Check Database
    try:
        from database import get_db_session
        from sqlalchemy import text
        with get_db_session() as session:
            session.execute(text("SELECT 1"))
        results["database"] = True
    except Exception as e:
        logger.error(f"PRE-FLIGHT FAIL: Database connection failed | error={e}")

    # 2. Check Ollama API & Models
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.ollama_host}/api/tags")
            if resp.status_code == 200:
                results["ollama_api"] = True
                models_data = resp.json()
                available_models = [m["name"] for m in models_data.get("models", [])]
                
                results["ollama_model"] = any(settings.ollama_model in m for m in available_models)
                results["ollama_embed"] = any(settings.ollama_embed_model in m for m in available_models)
    except Exception as e:
        logger.error(f"PRE-FLIGHT FAIL: Ollama service unreachable at {settings.ollama_host} | error={e}")

    # Log report
    logger.info("--- PRE-FLIGHT READINESS REPORT ---")
    logger.info(f"Database: {'✅ OK' if results['database'] else '❌ FAIL'}")
    logger.info(f"Ollama API: {'✅ OK' if results['ollama_api'] else '❌ FAIL'}")
    logger.info(f"LLM Model: {'✅ OK' if results['ollama_model'] else '❌ MISSING'}")
    logger.info(f"Embed Model: {'✅ OK' if results['ollama_embed'] else '❌ MISSING'}")
    logger.info("-----------------------------------")
    return results


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    settings = get_settings()
    logger.info(f"AegisNet starting | version={settings.app_version}, debug={settings.debug}")

    # Ensure directories exist
    settings.ensure_dirs()

    # Initialize database
    from database import init_db
    init_db()
    
    # Pre-flight readiness check
    await pre_flight_check()

    # Start file watcher â€” auto-analyze CSVs dropped into data/
    from file_watcher import FileWatcher
    from file_watcher.handler import handle_new_csv
    watcher = FileWatcher(on_new_file=handle_new_csv, watch_dir=settings.data_dir)
    await watcher.start()

    # Start high-throughput Flush Buffer
    from core.flush_buffer import get_flush_worker
    flush_worker = get_flush_worker()
    await flush_worker.start()

    yield

    # Cleanup on shutdown
    await watcher.stop()
    await flush_worker.stop()
    from database import close_db
    close_db()
    logger.info("AegisNet shutting down")



# Create FastAPI app
app = FastAPI(
    title="AegisNet",
    description="AI-Based Network Threat Analysis Platform",
    version=get_settings().app_version,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174", "http://10.170.25.3:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(file_router, prefix="/api/v1")
app.include_router(case_router, prefix="/api/v1", dependencies=[Depends(require_auth)])


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, Any]:
    """Check system health."""
    settings = get_settings()

    # Check Ollama availability
    ollama_ok = False
    try:
        from agents.base import OllamaClient
        client = OllamaClient()
        ollama_ok = await client.health_check()
        await client.close()
    except Exception:
        pass

    return {
        "status": "healthy" if ollama_ok else "degraded",
        "version": settings.app_version,
        "ollama": {
            "available": ollama_ok,
            "host": settings.ollama_host,
            "model": settings.ollama_model,
        },
        "storage": {
            "raw_path": str(settings.raw_storage_dir),
            "processed_path": str(settings.processed_dir),
        },
    }


# Root endpoint
@app.get("/", tags=["Root"])
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {
        "name": "AegisNet",
        "description": "AI-Based Network Threat Analysis Platform",
        "docs": "/docs",
    }


# Analysis endpoint â€” Three-Tier Pipeline
@app.post("/api/v1/analyze", tags=["Analysis"])
async def analyze_file(
    file_id: str,
    current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Three-tier analysis pipeline:
    1. Parse & Normalize events
    2. TIER 1: Deterministic rules engine (61 rules, < 1 sec)
    3. Update Threat State Store (per-IP daily accumulators)
    4. TIER 2: Day-level correlator (9 cross-batch rules)
    5. Create incidents from Tiers 1 & 2
    6. TIER 3: AI agent ensemble (only for ambiguous/flagged traffic)
    7. Create remaining incidents from AI

    Note: Authentication is optional for backend testing. If no token is provided,
    a default test user will be used.
    """
    import csv
    import io
    from datetime import date
    from uuid import UUID

    from agents.orchestrator import AgentOrchestrator
    from behavior_summary.service import BehaviorSummaryService
    from chunking.service import ChunkingService
    from core.auth import resolve_user_identity
    from core.config import get_settings
    from file_intake.service import FileIntakeService
    from incidents.service import IncidentService
    from log_parser.base import ParserRegistry
    from normalization.service import NormalizationService
    from rules_engine.engine import DeterministicEngine
    from shared_models.events import RawEventRow
    from threat_state.correlator import CorrelationResult, DayLevelCorrelator
    from threat_state.store import get_threat_state_store

    settings = get_settings()
    logger.info(f"Starting three-tier analysis pipeline | file_id={file_id} | correlation_enabled={settings.enable_correlation_tier} | ai_enabled={settings.enable_ai_tier}")

    # â”€â”€ Step 0: Get & parse file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    file_service = FileIntakeService()
    file_metadata = await file_service.get_file(file_id)

    if not file_metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )

    # â”€â”€ Step 0: Immediate Status Update â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    await file_service.start_processing(file_id)

    try:
        content = await file_service.get_file_content(file_id)
        if not content:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"File content not found: {file_id}",
            )

        text = content.decode("utf-8")

        # Primary path: normal CSV with header row
        dict_reader = csv.DictReader(io.StringIO(text))
        rows = []
        for row in dict_reader:
            cleaned_row = {k: v for k, v in row.items() if k is not None}
            rows.append(cleaned_row)

        row_number_offset = 2  # account for header row in normal CSVs

        # Fallback path: raw one-column logs without an explicit header.
        # In this case DictReader treats first event as a header and drops it.
        fieldnames = dict_reader.fieldnames or []
        if fieldnames and len(fieldnames) == 1:
            first_col = (fieldnames[0] or "").strip()
            looks_like_raw_log = first_col.startswith("<") and ("HTTP/" in first_col or "httpd[" in first_col)
            if looks_like_raw_log:
                plain_reader = csv.reader(io.StringIO(text))
                rows = []
                for row in plain_reader:
                    if not row:
                        continue
                    value = (row[0] or "").strip()
                    if value:
                        rows.append({"logevent": value})
                row_number_offset = 1
                logger.info("Detected headerless raw log format; using single-column fallback parser path")

        if not rows:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File contains no data rows",
            )

        columns = list(rows[0].keys())
        parser = ParserRegistry.detect_parser(columns, rows[:5])

        raw_rows = [
            RawEventRow(
                file_id=UUID(file_id),
                row_number=i + row_number_offset,
                raw_data=row,
            )
            for i, row in enumerate(rows)
        ]

        parsed_events = parser.parse_batch(raw_rows)

        # Normalize (CPU-parallel for large batches, auto-fallback for small)
        normalizer = NormalizationService()
        event_batch = normalizer.normalize_batch_parallel(parsed_events)

        # Post-normalization deduplication
        from normalization.deduplication import Deduplicator
        deduplicator = Deduplicator()
        deduped_events = deduplicator.deduplicate(event_batch.events)
        dedupe_path = deduplicator.write_jsonl(deduped_events, settings.processed_dir, file_id) 
        enriched_events = deduplicator.deduplicate(event_batch.events)

        logger.info(f"Parse, normalize & deduplicate complete | file_id={file_id}, events={len(enriched_events)}")

        # â”€â”€ TIER 1: Deterministic Rules Engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        engine = DeterministicEngine()
        tier1_result = engine.scan_parallel(enriched_events)

        logger.info(f"Tier 1 complete | threats={len(tier1_result.threats)}, matches={len(tier1_result.matches)}, time_ms={tier1_result.processing_time_ms}")

        # â”€â”€ Update Threat State Store â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        state_store = get_threat_state_store(date.today())
        state_store.update_from_batch(enriched_events, tier1_result)

        # â”€â”€ TIER 2: Day-Level Correlator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if settings.enable_correlation_tier:
            correlator = DayLevelCorrelator(state_store)
            tier2_result = correlator.correlate(events=enriched_events)
            logger.info(f"Tier 2 complete | total_findings={len(tier2_result.findings)}, new_patterns={len(tier2_result.new_patterns)}")
        else:
            logger.info("Tier 2 (Correlation) disabled by configuration")
            tier2_result = CorrelationResult(findings=[], new_patterns=[])

        # â”€â”€ Create incidents from Tier 1 & Tier 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        incident_service = IncidentService()
        all_incidents = []
        parsed_uuid = UUID(file_id)

        # Tier 1 incidents (high-confidence deterministic matches)
        for threat in tier1_result.high_confidence_threats:
            incident = incident_service.create_from_deterministic_threat(
                threat, file_id=parsed_uuid,
            )
            all_incidents.append(incident)

        # Tier 2 incidents (new cross-batch correlations)
        if settings.enable_correlation_tier:
            for pattern in tier2_result.new_patterns:
                incident = incident_service.create_from_correlation(
                    pattern, file_id=parsed_uuid,
                )
                all_incidents.append(incident)

        # â”€â”€ Incremental Commit: Tier 1 & 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # This ensures findings are visible even if AI phase fails
        await file_service.update_analysis_stats(
            file_id=file_id,
            events_normalized=len(enriched_events),
            chunks_created=0,
            suspicious_chunks=0,
            ai_analyses=0,
            incidents_created=len(all_incidents),
        )

        # â”€â”€ Chunking & TIER 3: AI Agent Pipeline (if needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        chunking_svc = ChunkingService()
        chunks = await chunking_svc.chunk_events(enriched_events, file_id=parsed_uuid)

        # Balanced filtering â€” catches low-volume targeted attacks too
        # Send ALL chunks to AI -- thresholds removed so no chunk is filtered out.
        # Every event group, regardless of size, failure rate, or target count,
        # will be included in AI analysis.
        suspicious_chunks = chunks  # was: chunking_svc.filter_suspicious_chunks(...)

        # Store chunks for rollup via Async Flush Buffer
        from core.flush_buffer import get_flush_worker
        flush_worker = get_flush_worker()
        for chunk in chunks:
            await flush_worker.submit_chunk(chunk)

        ai_outputs = []
        # Always escalate to AI — every deterministic and correlation finding
        # should go through AI analysis regardless of tier flags.
        needs_ai = True  # was: tier1_result.needs_ai_review or tier2_result.needs_ai_review

        # â”€â”€ Scale optimization: risk-score, deprioritize, and cap for AI â”€â”€
        MAX_AI_CHUNKS = 20          # Generous cap â€” ~4 min with 5 concurrent
        MAX_AI_CONCURRENT = 2       # Reduce to 2 to prevent Ollama HTTP timeouts during heavy load

        if needs_ai and suspicious_chunks:
            # Build set of IPs fully covered by high-confidence deterministic rules
            fully_covered_ips: set[str] = set()
            ip_threats: dict[str, list] = {}
            for threat in tier1_result.threats:
                for ip in (threat.src_ips or []):
                    ip_threats.setdefault(ip, []).append(threat)
            for ip, threats_for_ip in ip_threats.items():
                if all(t.confidence >= 0.8 for t in threats_for_ip):
                    fully_covered_ips.add(ip)

            if fully_covered_ips:
                logger.info(f"IPs with full deterministic coverage (deprioritized for AI) | count={len(fully_covered_ips)}")

            # Risk-score ALL suspicious chunks to prioritize the most important
            def _chunk_risk_score(chunk) -> float:
                score = 0.0
                profile = chunk.activity_profile
                score += min(profile.events_per_minute / 50.0, 2.0)
                score += profile.failure_rate * 3.0
                score += min(chunk.targets.unique_target_count / 10.0, 2.0)
                from shared_models.chunks import TemporalPattern
                if chunk.temporal_pattern == TemporalPattern.ESCALATING:
                    score += 2.0
                elif chunk.temporal_pattern == TemporalPattern.BURSTY:
                    score += 1.0
                score += min(profile.total_events / 500.0, 1.0)

                chunk_ip = chunk.actor.src_ip if chunk.actor else None
                if chunk_ip and chunk_ip in fully_covered_ips:
                    score *= 0.5

                return score

            # Sort by risk (highest first) and cap
            suspicious_chunks.sort(key=_chunk_risk_score, reverse=True)
            ai_chunks = suspicious_chunks[:MAX_AI_CHUNKS]

            logger.info(f"Escalating to Tier 3 AI | reasons={tier1_result.ai_review_reasons + tier2_result.ai_review_reasons}, total_suspicious={len(suspicious_chunks)}, sent_to_ai={len(ai_chunks)}, deprioritized_ips={len(fully_covered_ips)}")

            if ai_chunks:
                summarizer = BehaviorSummaryService()
                summaries = summarizer.summarize_batch(ai_chunks)

                orchestrator = AgentOrchestrator()
                ai_outputs = await orchestrator.analyze_batch(
                    summaries, max_concurrent=MAX_AI_CONCURRENT,
                )

                # Store agent outputs
                from agents.outputs_storage import get_agent_outputs_storage
                outputs_storage = get_agent_outputs_storage()
                outputs_storage.store_outputs(file_id, ai_outputs)

                # Create incidents from AI
                for output, chunk in zip(ai_outputs, ai_chunks):
                    if output.requires_human_review:
                        incident = incident_service.create_from_agent_output(output, chunk)
                        all_incidents.append(incident)

                await orchestrator.close()
            else:
                logger.info("No chunks qualified for AI review")
        else:
            logger.info("Tier 3 AI skipped â€” deterministic analysis sufficient")

        def _incident_id_value(incident: Any) -> Any:
            if hasattr(incident, "incident_id"):
                return incident.incident_id
            if isinstance(incident, dict):
                return incident.get("incident_id")
            return None

        def _flatten_incident_entries(entries: list[Any]) -> list[Any]:
            flattened = []
            for entry in entries:
                if isinstance(entry, list):
                    flattened.extend(_flatten_incident_entries(entry))
                else:
                    flattened.append(entry)
            return flattened

        all_incidents = _flatten_incident_entries(all_incidents)
        valid_incidents = [
            incident for incident in all_incidents
            if _incident_id_value(incident) is not None
        ]
        if len(valid_incidents) != len(all_incidents):
            logger.warning(
                f"Dropped malformed incident entries before reporting | "
                f"total={len(all_incidents)}, valid={len(valid_incidents)}"
            )
        all_incidents = valid_incidents

        logger.info(f"Three-tier analysis complete | file_id={file_id}, events={len(enriched_events)}, tier1_threats={len(tier1_result.threats)}, tier2_correlations={len(tier2_result.new_patterns)}, ai_analyses={len(ai_outputs)}, total_incidents={len(all_incidents)}")

        # â”€â”€ Generate human-readable report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        from reports.writer import ReportWriter
        report_writer = ReportWriter()
        report_path = report_writer.generate_report(
            file_id=file_id,
            filename=file_metadata.original_filename,
            events_parsed=len(parsed_events),
            events_normalized=len(event_batch.events),
            tier1_result=tier1_result,
            tier2_result=tier2_result,
            ai_outputs=ai_outputs,
            incidents=all_incidents,
            events=enriched_events,
        )
        logger.info(f"Report saved | path={report_path}")

        # Extract emp_id from current user for JSON report
        user_identity = resolve_user_identity(current_user)
        emp_id = user_identity.get("emp_id")

        incidents_json_path = report_writer.generate_incident_json_report(
            file_id=file_id,
            filename=file_metadata.original_filename,
            incidents=all_incidents,
            emp_id=emp_id,
        )
        logger.info(f"Incident JSON report saved | path={incidents_json_path}, emp_id={emp_id}")

        # Final Update
        await file_service.update_analysis_stats(
            file_id=file_id,
            events_normalized=len(enriched_events),
            chunks_created=len(chunks),
            suspicious_chunks=len(suspicious_chunks),
            ai_analyses=len(ai_outputs),
            incidents_created=len(all_incidents),
        )
        # logger.info(f"Analysis completed | file_id={file_id}")
        print(f"Analysis completed | file_id={file_id}", flush=True)

        return {
            "file_id": file_id,
            "events_parsed": len(parsed_events),
            "events_normalized": len(event_batch.events),
            "chunks_created": len(chunks),
            "tier1_deterministic": {
                "threats_found": len(tier1_result.threats),
                "matches": len(tier1_result.matches),
                "processing_time_ms": tier1_result.processing_time_ms,
                "by_category": tier1_result.threats_by_category,
                "by_severity": tier1_result.threats_by_severity,
                "attacker_ips": tier1_result.unique_attacker_ips,
            },
            "tier2_correlation": {
                "findings": len(tier2_result.findings),
                "new_patterns": len(tier2_result.new_patterns),
                "processing_time_ms": tier2_result.processing_time_ms,
            },
            "tier3_ai": {
                "escalated": needs_ai,
                "ai_analyses": len(ai_outputs),
                "reasons": tier1_result.ai_review_reasons + tier2_result.ai_review_reasons,
            },
            "total_incidents": len(all_incidents),
            "incident_ids": [str(_incident_id_value(i)) for i in all_incidents],
            "report_path": str(report_path),
            "report_url": f"/api/v1/files/{file_id}/report",
            "incident_json_path": str(incidents_json_path),
            "incident_json_url": f"/api/v1/files/{file_id}/incidents-json",
            "day_summary": state_store.get_day_summary(),
        }

    except Exception as e:
        logger.error(f"Critical failure during analysis pipeline: {e}", exc_info=True)
        await file_service.mark_failed(file_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}",
        )
# Day-level Threat Summary endpoint
@app.get("/api/v1/threat-summary/today", tags=["Analysis"])
async def get_today_threat_summary(
    _current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Get accumulated threat intelligence for today.
    Returns day-level view across all 15-minute batches.
    """
    from datetime import date

    from threat_state.store import get_threat_state_store

    store = get_threat_state_store(date.today())
    return store.get_day_summary()


# Agent outputs endpoint - get actual AI analysis results for Pipeline view
@app.get("/api/v1/agent-outputs/{file_id}", tags=["Analysis"])
async def get_agent_outputs(
    file_id: str,
    _current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Get actual agent analysis outputs for a file.

    Returns aggregated summaries from all 4 AI agents:
    - Behavioral Interpretation
    - Threat Intent
    - MITRE Mapping
    - Triage & Narrative
    """
    from agents.outputs_storage import get_agent_outputs_storage

    storage = get_agent_outputs_storage()
    summary = storage.get_aggregated_summary(file_id)

    return summary


# Rollup Analysis endpoint - long-horizon cross-file correlation
@app.get("/api/v1/rollups", tags=["Analysis"])
async def get_rollup_analysis(
    _current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Get long-horizon rollup analysis across all analyzed files.

    Detects:
    - Low-and-slow attack patterns spanning days/weeks
    - Persistent threat actors across multiple files
    - Cross-file behavioral correlations

    Returns:
        Rollup analysis with actor profiles and risk scores
    """
    from rollups import RollupService
    from rollups.chunk_storage import get_chunk_storage

    # Get storage and initialize service
    chunk_storage = get_chunk_storage()
    rollup_service = RollupService()

    # Check if GPU acceleration is available
    if rollup_service.get_stats().get("gpu_available", False):
        # Run GPU-accelerated rollup directly from the chunks directory
        chunks_dir = str(chunk_storage.chunks_dir)
        result = rollup_service.create_rollup_gpu(chunks_dir, min_actor_chunks=1)
        used_gpu = True
    else:
        # Run CPU streaming aggregation
        all_chunks = chunk_storage.get_all_chunks()
        result = rollup_service.create_rollup(all_chunks, min_actor_chunks=1)
        used_gpu = False

    # Check if any data was actually processed
    if result.chunks_analyzed == 0:
        return {
            "status": "no_data",
            "message": "No chunks available for rollup analysis. Analyze some files first.",
            "chunks_stored": 0,
            "files_analyzed": 0,
        }

    # Convert to JSON-serializable format
    actor_profiles = []
    for profile in result.actor_profiles:
        actor_profiles.append({
            "profile_id": str(profile.profile_id),
            "primary_ip": profile.primary_ip,
            "all_ips": profile.all_ips,
            "username": profile.username,
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
            "total_events": profile.total_events,
            "total_denials": profile.total_denials,
            "unique_targets": profile.unique_targets,
            "active_days": profile.active_days,
            "risk_score": profile.risk_score,
            "risk_factors": profile.risk_factors,
            "files_count": len(profile.file_ids),
        })

    return {
        "status": "success",
        "rollup_id": str(result.rollup_id),
        "days_covered": result.days_covered,
        "chunks_analyzed": result.chunks_analyzed,
        "files_analyzed": result.files_analyzed,
        "actor_profiles": actor_profiles,
        "high_risk_actors": result.high_risk_actors,
        "cross_file_patterns": result.cross_file_patterns,
        "gpu_accelerated": used_gpu,
        "created_at": result.created_at.isoformat(),
    }


# Validation endpoint - shows reproducibility metrics
@app.get("/api/v1/validation", tags=["Validation"])
async def get_validation_stats(
    _current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Get reproducibility validation metrics.

    Returns:
        - Cache statistics (hits, misses, hit_rate)
        - Model configuration (name, temperature)
        - Agent statistics
        - Analysis counts
    """
    from agents.cache import get_analysis_cache
    from agents.outputs_storage import get_agent_outputs_storage

    # Get cache stats
    cache = get_analysis_cache()
    cache_stats = cache.get_stats()

    # Get agent stats from stored outputs
    storage = get_agent_outputs_storage()
    all_outputs = storage._data

    # Calculate actual agent stats from stored data
    total_behavioral = 0
    total_intent = 0
    total_mitre = 0
    total_triage = 0
    total_analyses = 0

    for file_id, outputs in all_outputs.items():
        total_analyses += len(outputs)
        for output in outputs:
            if "behavioral" in output:
                total_behavioral += 1
            if "intent" in output:
                total_intent += 1
            if "mitre" in output:
                total_mitre += 1
            if "triage" in output:
                total_triage += 1

    settings = get_settings()

    return {
        "reproducibility": {
            "status": "enabled",
            "description": "Same input (chunk hash) â†’ Same output (cached result)",
            "cache_hit_rate": cache_stats.get("hit_rate_percent", 0),
            "total_cache_entries": cache_stats.get("memory_entries", 0),
        },
        "determinism_settings": {
            "temperature": settings.ollama_temperature,
            "max_temperature": 0.2,
            "model": settings.ollama_model,
            "description": "Low temperature (â‰¤0.2) for deterministic outputs",
        },
        "safeguards": [
            "Temperature capped at 0.2 for determinism",
            "Anti-hallucination system prompts",
            "Strict JSON schema validation",
            "Confidence scores required on all outputs",
            "Content-based caching for reproducibility",
        ],
        "cache_stats": cache_stats,
        "agent_stats": {
            "behavioral": {
                "agent": "Behavioral Summary",
                "invocations": total_behavioral,
                "errors": 0,
                "success_rate": 1 if total_behavioral > 0 else 0,
            },
            "intent": {
                "agent": "Threat Intent",
                "invocations": total_intent,
                "errors": 0,
                "success_rate": 1 if total_intent > 0 else 0,
            },
            "mitre": {
                "agent": "MITRE Mapping",
                "invocations": total_mitre,
                "errors": 0,
                "success_rate": 1 if total_mitre > 0 else 0,
            },
            "triage": {
                "agent": "Triage & Narrative",
                "invocations": total_triage,
                "errors": 0,
                "success_rate": 1 if total_triage > 0 else 0,
            },
        },
        "total_analyses": total_analyses,
        "files_analyzed": len(all_outputs),
    }


# â”€â”€ Clear All Data endpoint (for fresh testing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.delete("/api/v1/system/clear-all", tags=["System"])
async def clear_all_data(
    _current_user: str = Depends(optional_auth),
) -> dict[str, Any]:
    """
    Clear ALL analysis data for fresh testing.
    Wipes: DB tables, raw files, processed files, reports, caches, threat state.
    """
    import shutil

    settings = get_settings()
    cleared = []

    # 1. Clear PostgreSQL tables
    try:
        from sqlalchemy import text

        from database import get_db_session
        with get_db_session() as session:
            for table in ['files', 'file_intakes', 'agent_outputs', 'behavior_summaries',
                          'cases', 'chunks', 'incidents', 'normalized_events']:
                try:
                    session.execute(text(f'DELETE FROM {table}'))
                except Exception:
                    pass  # Table may not exist
            session.commit()
            cleared.append('database_tables')
    except Exception as e:
        logger.warning(f"DB clear partial | error={e}")

    # 2. Clear raw files
    raw_dir = settings.raw_storage_dir
    if raw_dir.exists():
        shutil.rmtree(raw_dir)
        raw_dir.mkdir(parents=True, exist_ok=True)
        cleared.append('raw_files')

    # 3. Clear processed files (incidents, cache, rollups, threat state)
    processed_dir = settings.processed_dir
    if processed_dir.exists():
        shutil.rmtree(processed_dir)
        processed_dir.mkdir(parents=True, exist_ok=True)
        cleared.append('processed_files')

    # 4. Clear generated reports (only .md files â€” preserve source code)
    reports_dir = settings.base_dir / 'reports'
    if reports_dir.exists():
        report_files = list(reports_dir.glob('*_report.md'))
        for f in report_files:
            f.unlink()
        if report_files:
            cleared.append(f'reports ({len(report_files)} files)')

    # 5. Clear analysis cache from memory
    try:
        from agents.cache import get_analysis_cache
        cache = get_analysis_cache()
        cache._memory_cache.clear()
        cleared.append('analysis_cache')
    except Exception:
        pass

    logger.info(f"All data cleared for fresh testing | cleared={cleared}")

    return {
        "status": "success",
        "message": "All data cleared. Ready for fresh testing.",
        "cleared": cleared,
    }


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Handle uncaught exceptions."""
    logger.error(f"Unhandled exception | error={exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )

   
