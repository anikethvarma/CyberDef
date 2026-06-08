"""
AegisNet - AI-Based Network Threat Analysis Platform

Main FastAPI application entry point.
"""


from __future__ import annotations

import asyncio
import csv
import functools
from datetime import date
import io
import shutil
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Set
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
# pyrefly: ignore [missing-import]
import httpx
# pyrefly: ignore [missing-import]
from sqlalchemy import text
# pyrefly: ignore [missing-import]
import uvicorn

from agents.base import OllamaClient
from agents.cache import get_analysis_cache
from agents.orchestrator import AgentOrchestrator
from agents.outputs_storage import get_agent_outputs_storage
from behavior_summary.service import BehaviorSummaryService
from case_api.routes import router as case_router
from chunking.service import ChunkingService
from core.auth import optional_auth, require_auth, resolve_user_identity
from core.auth_routes import router as auth_router
from core.config import get_settings
from core.flush_buffer import get_flush_worker
from core.ip_filter import is_ip_excluded, is_zscaler_ip
from core.logging import get_logger, setup_logging
from database import close_db, get_db_session, init_db
from file_intake.routes import router as file_router
from file_intake.service import FileIntakeService
from file_watcher import FileWatcher
from file_watcher.handler import handle_new_csv
from incidents.service import IncidentService
from log_parser.base import ParserRegistry
from normalization.deduplication import Deduplicator
from normalization.service import NormalizationService
from reports.writer import ReportWriter
from rollups import RollupService
from rollups.chunk_storage import get_chunk_storage
from rules_engine.engine import DeterministicEngine
from shared_models.chunks import TemporalPattern
from shared_models.events import RawEventRow
from threat_state.correlator import CorrelationResult, DayLevelCorrelator
from threat_state.store import get_threat_state_store

# Initialize logging
setup_logging()
logger = get_logger(__name__)


async def pre_flight_check() -> Dict[str, bool]:
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
        with get_db_session() as session:
            session.execute(text("SELECT 1"))
        results["database"] = True
    except Exception as e:
        logger.error(f"PRE-FLIGHT FAIL: Database connection failed | error={e}")

    # 2. Check Ollama API & Models
    try:
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
    init_db()
    
    # Pre-flight readiness check
    await pre_flight_check()

    # Start file watcher — auto-analyze CSVs dropped into data/
    watcher = FileWatcher(on_new_file=handle_new_csv, watch_dir=settings.data_dir)
    await watcher.start()

    # Start high-throughput Flush Buffer
    flush_worker = get_flush_worker()
    await flush_worker.start()

    yield

    # Cleanup on shutdown
    await watcher.stop()
    await flush_worker.stop()
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
async def health_check() -> Dict[str, Any]:
    """Check system health."""
    settings = get_settings()

    # Check Ollama availability
    ollama_ok = False
    try:
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
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {
        "name": "AegisNet",
        "description": "AI-Based Network Threat Analysis Platform",
        "docs": "/docs",
    }


# Analysis endpoint — Three-Tier Pipeline
@app.post("/api/v1/analyze", tags=["Analysis"])
async def analyze_file(
    file_id: str,
    current_user: str = Depends(optional_auth),
) -> Dict[str, Any]:
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
    settings = get_settings()
    logger.info(f"Starting three-tier analysis pipeline | file_id={file_id} | correlation_enabled={settings.enable_correlation_tier} | ai_enabled={settings.enable_ai_tier}")

    # — Step 0: Get & parse file ————————————————————————————————————————————
    file_service = FileIntakeService()
    file_metadata = await file_service.get_file(file_id)

    if not file_metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File not found: {file_id}",
        )

    # — Step 0: Immediate Status Update ————————————————————————————————————
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

        loop = asyncio.get_event_loop()

        parsed_events = await loop.run_in_executor(
            None, parser.parse_batch, raw_rows
        )

        # Normalize (CPU-parallel for large batches, auto-fallback for small)
        normalizer = NormalizationService()
        event_batch = await loop.run_in_executor(
            None, normalizer.normalize_batch_parallel, parsed_events
        )

        # Post-normalization deduplication
        deduplicator = Deduplicator()
        deduped_events = await loop.run_in_executor(
            None, deduplicator.deduplicate, event_batch.events
        )
        dedupe_path = await loop.run_in_executor(
            None, deduplicator.write_jsonl, deduped_events, settings.processed_dir, file_id
        )
        enriched_events = await loop.run_in_executor(
            None, deduplicator.deduplicate, event_batch.events
        )

        logger.info(f"Parse, normalize & deduplicate complete | file_id={file_id}, events={len(enriched_events)}")

        # — TIER 1: Deterministic Rules Engine ————————————————————————————————
        engine = DeterministicEngine()
        tier1_result = await loop.run_in_executor(
            None, engine.scan_parallel, enriched_events
        )

        logger.info(f"Tier 1 complete | threats={len(tier1_result.threats)}, matches={len(tier1_result.matches)}, time_ms={tier1_result.processing_time_ms}")

        # — Update Threat State Store ——————————————————————————————————————————
        state_store = get_threat_state_store(date.today())
        await loop.run_in_executor(
            None, state_store.update_from_batch, enriched_events, tier1_result
        )

        # — TIER 2: Day-Level Correlator ——————————————————————————————————————
        if settings.enable_correlation_tier:
            correlator = DayLevelCorrelator(state_store)
            tier2_result = await loop.run_in_executor(
                None, correlator.correlate, enriched_events
            )
            logger.info(f"Tier 2 complete | total_findings={len(tier2_result.findings)}, new_patterns={len(tier2_result.new_patterns)}")
        else:
            logger.info("Tier 2 (Correlation) disabled by configuration")
            tier2_result = CorrelationResult(findings=[], new_patterns=[])

        # — Collect IPs from Tier 1 & Tier 2 findings ——————————————————————————
        # All findings (Tier 1 + Tier 2) go to AI for TP/FP validation.
        # Incidents are ONLY created after AI confirms a finding is a True Positive.
        incident_service = IncidentService()
        all_incidents = []
        parsed_uuid = UUID(file_id)

        def _process_correlation_patterns(patterns, ai_confirmed_ips_set=None):
            if not settings.enable_correlation_tier:
                return
            from collections import defaultdict
            from threat_state.correlator import CorrelationFinding
            patterns_by_ip = defaultdict(list)
            for pattern in patterns:
                patterns_by_ip[pattern.src_ip].append(pattern)
            
            for ip, ip_patterns in patterns_by_ip.items():
                if len(ip_patterns) == 1:
                    pattern_to_log = ip_patterns[0]
                else:
                    categories = list(set(p.category for p in ip_patterns))
                    severities = [p.severity for p in ip_patterns]
                    sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                    highest_sev = max(severities, key=lambda s: sev_rank.get(s, 0))
                    desc = f"Multi-vector correlation incident encompassing {len(ip_patterns)} findings: " + " | ".join(p.description for p in ip_patterns)
                    combined_evidence = {}
                    for p in ip_patterns:
                        combined_evidence[p.correlation_rule] = p.evidence
                        
                    pattern_to_log = CorrelationFinding(
                        correlation_rule="composite_multi_vector",
                        category=", ".join(categories),
                        severity=highest_sev,
                        confidence=max(p.confidence for p in ip_patterns),
                        description=desc,
                        src_ip=ip,
                        evidence=combined_evidence,
                        detection_tier="correlation"
                    )

                incident = incident_service.create_from_correlation(
                    pattern_to_log, file_id=parsed_uuid,
                )
                if incident:
                    if ai_confirmed_ips_set is not None:
                        if pattern_to_log.src_ip not in ai_confirmed_ips_set:
                            fp_remark = _extract_fp_remark(pattern_to_log.src_ip or "")
                            logger.info(
                                f"Tier 2 finding dropped by AI (FP), lodging as human review | rule={pattern_to_log.correlation_rule}, ip={pattern_to_log.src_ip} | remark={fp_remark}"
                            )
                            incident.detection_tier = "AI Analyzed - needs human review"
                        else:
                            incident.detection_tier = "Correlation"
                    all_incidents.append(incident)

        # Collect source IPs from Tier 1 threats
        incident_ips: set[str] = set()
        for threat in tier1_result.threats:
            if threat.src_ip:
                incident_ips.add(threat.src_ip)
            for ip in threat.src_ips:
                if ip:
                    incident_ips.add(ip)
        # Collect source IPs from Tier 2 correlation findings
        if settings.enable_correlation_tier:
            for pattern in tier2_result.findings:
                if pattern.src_ip:
                    incident_ips.add(pattern.src_ip)

        # Map IP -> Tier1 threats and IP -> Tier2 patterns for post-AI incident creation
        ip_to_tier1_threats: Dict[str, list] = {}
        for threat in tier1_result.threats:
            ip = threat.src_ip or ""
            ip_to_tier1_threats.setdefault(ip, []).append(threat)
            for extra_ip in threat.src_ips:
                if extra_ip:
                    ip_to_tier1_threats.setdefault(extra_ip, []).append(threat)

        ip_to_tier2_patterns: Dict[str, list] = {}
        if settings.enable_correlation_tier:
            for pattern in tier2_result.new_patterns:
                if pattern.src_ip:
                    ip_to_tier2_patterns.setdefault(pattern.src_ip, []).append(pattern)

        # — Incremental Commit: placeholder before AI ——————————————————————————
        # Provides a progress update in the UI even before AI completes.
        await file_service.update_analysis_stats(
            file_id=file_id,
            events_normalized=len(enriched_events),
            chunks_created=0,
            suspicious_chunks=0,
            ai_analyses=0,
            incidents_created=0,
        )

        # — Chunking ———————————————————————————————————————————————————————————
        chunking_svc = ChunkingService()
        chunks = await chunking_svc.chunk_events(enriched_events, file_id=parsed_uuid)

        # Only send chunks to AI if they belong to Tier 1 or Tier 2 finding IPs
        suspicious_chunks = []
        for chunk in chunks:
            ip = chunk.actor.src_ip if chunk.actor else None
            ips = chunk.actor.src_ips if chunk.actor else []
            if (ip and ip in incident_ips) or any(i in incident_ips for i in ips if i):
                suspicious_chunks.append(chunk)

        # Initialise dropped_threats here so it is always defined regardless
        # of which execution path (AI / fallback / skipped) is taken below.
        dropped_threats: list = []


        # ——— Build rule-specific context for Chunks ————————————
        # Build event_id → list-of-rule-dicts from Tier 1 and Tier 2 findings.
        event_to_flagged_rules: Dict[UUID, list] = {}
        for threat in tier1_result.threats:
            rule_entry = {
                "tier": "Tier 1 (Deterministic)",
                "rule": threat.rule_name,
                "category": threat.category,
                "severity": threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity),
                "description": getattr(threat, "description", threat.rule_name),
                "evidence": getattr(threat, "sample_evidence", []),
            }
            for event_id in getattr(threat, "affected_event_ids", []):
                event_to_flagged_rules.setdefault(event_id, []).append(rule_entry)

        if settings.enable_correlation_tier:
            for pattern in tier2_result.new_patterns:
                rule_entry = {
                    "tier": "Tier 2 (Correlation)",
                    "rule": pattern.correlation_rule,
                    "category": getattr(pattern, "category", "correlation"),
                    "severity": getattr(pattern, "severity", "medium"),
                    "description": getattr(pattern, "description", pattern.correlation_rule),
                    "evidence": getattr(pattern, "evidence", {}),
                }
                for event_id in getattr(pattern, "affected_event_ids", []):
                    event_to_flagged_rules.setdefault(event_id, []).append(rule_entry)

        # Store chunks for rollup via Async Flush Buffer
        flush_worker = get_flush_worker()
        for i, chunk in enumerate(chunks):
            # Stamp BehavioralChunk with flagged rules that actually fired in this chunk's events
            rules: list = []
            seen_rules: set = set()
            for event_id in getattr(chunk, "source_event_ids", []):
                for r in event_to_flagged_rules.get(event_id, []):
                    key = (r["tier"], r["rule"])
                    if key not in seen_rules:
                        rules.append(r)
                        seen_rules.add(key)
            if rules:
                chunk.flagged_rules = rules
            
            await flush_worker.submit_chunk(chunk)

        ai_outputs = []
        needs_ai = settings.enable_ai_tier and bool(incident_ips)

        # — Scale optimization: risk-score, deprioritize, and cap for AI ———————
        MAX_AI_CHUNKS = 1000        # Generous cap — ~4 min with 5 concurrent
        MAX_AI_CONCURRENT = 2       # Reduce to 2 to prevent Ollama HTTP timeouts during heavy load

        if needs_ai and suspicious_chunks:
            # Build set of IPs fully covered by high-confidence deterministic rules
            fully_covered_ips: Set[str] = set()
            ip_threats: Dict[str, list] = {}
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
                if chunk.temporal_pattern == TemporalPattern.ESCALATING:
                    score += 2.0
                elif chunk.temporal_pattern == TemporalPattern.BURSTY:
                    score += 1.0
                score += min(profile.total_events / 500.0, 1.0)

                chunk_ip = chunk.actor.src_ip if chunk.actor else None
                chunk_ips = chunk.actor.src_ips if chunk.actor else []
                is_incident_chunk = (chunk_ip and chunk_ip in incident_ips) or any(i in incident_ips for i in chunk_ips if i)
                if is_incident_chunk:
                    score += 100.0

                if chunk_ip and chunk_ip in fully_covered_ips:
                    score *= 0.5

                return score

            # Sort by risk (highest first) and cap
            suspicious_chunks.sort(key=_chunk_risk_score, reverse=True)
            ai_chunks = suspicious_chunks[:MAX_AI_CHUNKS]

            logger.info(f"Escalating to Tier 3 AI | reasons={tier1_result.ai_review_reasons + tier2_result.ai_review_reasons}, total_suspicious={len(suspicious_chunks)}, sent_to_ai={len(ai_chunks)}, deprioritized_ips={len(fully_covered_ips)}")

            if ai_chunks:
                summarizer = BehaviorSummaryService()
                summaries = await loop.run_in_executor(
                    None, summarizer.summarize_batch, ai_chunks
                )

                orchestrator = AgentOrchestrator()
                ai_outputs = await orchestrator.analyze_batch(
                    summaries, max_concurrent=MAX_AI_CONCURRENT,
                )

                # Build chunk lookup once — used by both the IP-stamping loop
                # below AND the TP/FP validation loop that follows.
                chunk_id_to_chunk = {c.chunk_id: c for c in ai_chunks}

                # Stamp each AgentOutput with the chunk's source IP so the report
                # writer can group AI analyses by IP without relying on the AI to
                # extract it from its own analysis (which is often null/unreliable).
                # Using model_copy(update=...) is the correct Pydantic v2 pattern —
                # direct attribute mutation raises a validation error on strict models.
                stamped: list = []
                for ai_out in ai_outputs:
                    src_chunk = chunk_id_to_chunk.get(ai_out.chunk_id)
                    if src_chunk and src_chunk.actor:
                        ai_out = ai_out.model_copy(update={
                            "src_ip": src_chunk.actor.src_ip,
                            "src_ips": list(src_chunk.actor.src_ips or []),
                        })
                    stamped.append(ai_out)
                ai_outputs = stamped

                # Store agent outputs (used for validation in UI)
                outputs_storage = get_agent_outputs_storage()
                outputs_storage.store_outputs(file_id, ai_outputs)

                # — AI-gated incident creation ——————————————————————————————————
                # Build a set of IPs that AI confirmed as True Positives
                # (i.e., at least one chunk for that IP was flagged as suspicious).
                ai_confirmed_ips: Set[str] = set()
                for ai_out in ai_outputs:
                    chunk = chunk_id_to_chunk.get(ai_out.chunk_id)
                    if not chunk:
                        continue
                    triage = ai_out.triage
                    behavioral = ai_out.behavioral
                    # Use behavioral agent's TP/FP decision (triage no longer has suspicious field)
                    is_tp = behavioral and behavioral.is_suspicious
                    if is_tp:
                        if chunk.actor.src_ip:
                            ai_confirmed_ips.add(chunk.actor.src_ip)
                        for extra_ip in (chunk.actor.src_ips or []):
                            if extra_ip:
                                ai_confirmed_ips.add(extra_ip)

                logger.info(
                    f"AI validation complete | confirmed_ips={len(ai_confirmed_ips)}, "
                    f"total_finding_ips={len(incident_ips)}, "
                    f"dropped_ips={len(incident_ips - ai_confirmed_ips)}"
                )

                # Build a quick lookup: IP -> list of AI outputs (for drop-reason extraction)
                ip_to_ai_outputs: Dict[str, list] = {}
                for ai_out in ai_outputs:
                    _out_ip = getattr(ai_out, "src_ip", None)
                    if _out_ip:
                        ip_to_ai_outputs.setdefault(_out_ip, []).append(ai_out)

                def _extract_fp_remark(ip: str) -> str:
                    """Pull the best LLM explanation for why this IP's threat was dropped."""
                    remarks = []
                    for _out in ip_to_ai_outputs.get(ip, []):
                        b = getattr(_out, "behavioral", None)
                        tr = getattr(_out, "triage", None)
                        if b and getattr(b, "reasoning", None):
                            remarks.append(b.reasoning)
                        if tr and getattr(tr, "risk_reason", None):
                            remarks.append(tr.risk_reason)
                    return " | ".join(dict.fromkeys(r for r in remarks if r)) or "LLM assessed as false positive (no detailed reasoning captured)"

                # Collect dropped threats with LLM remarks for the report
                # (dropped_threats was already initialised above; we append to it here)

                # Create Tier 1 incidents
                for threat in tier1_result.threats:
                    threat_ip = threat.src_ip or ""
                    confirmed = (
                        threat_ip in ai_confirmed_ips
                        or any(ip in ai_confirmed_ips for ip in threat.src_ips if ip)
                    )
                    
                    incident = incident_service.create_from_deterministic_threat(
                        threat, file_id=parsed_uuid,
                    )
                    if incident:
                        if not confirmed:
                            fp_remark = _extract_fp_remark(threat_ip)
                            logger.info(
                                f"Tier 1 finding dropped by AI (FP), lodging as human review | rule={threat.rule_name}, ip={threat.src_ip} | remark={fp_remark}"
                            )
                            incident.detection_tier = "AI Analyzed - needs human review"
                        else:
                            ai_outs = ip_to_ai_outputs.get(threat_ip, [])
                            if ai_outs:
                                max_conf = max((out.overall_confidence for out in ai_outs), default=0.0)
                                incident.detection_tier = "AI Analyzed" if max_conf >= 0.7 else "AI Analyzed - needs human review"
                        all_incidents.append(incident)

                # Create Tier 2 incidents
                _process_correlation_patterns(tier2_result.new_patterns, ai_confirmed_ips)

                await orchestrator.close()
            else:
                logger.info("No chunks qualified for AI review — falling back to direct incident creation")
                # Fallback: no chunks to review, create incidents directly
                for threat in tier1_result.threats:
                    incident = incident_service.create_from_deterministic_threat(
                        threat, file_id=parsed_uuid,
                    )
                    if incident:
                        all_incidents.append(incident)
                _process_correlation_patterns(tier2_result.new_patterns, None)
        else:
            logger.info("Tier 3 AI skipped — creating incidents directly from deterministic findings")
            # AI tier disabled or no findings: create incidents directly from Tier 1 & Tier 2
            for threat in tier1_result.threats:
                incident = incident_service.create_from_deterministic_threat(
                    threat, file_id=parsed_uuid,
                )
                if incident:
                    all_incidents.append(incident)
            _process_correlation_patterns(tier2_result.new_patterns, None)

        def _incident_id_value(incident: Any) -> Any:
            if hasattr(incident, "incident_id"):
                return incident.incident_id
            if isinstance(incident, dict):
                return incident.get("incident_id")
            return None

        def _flatten_incident_entries(entries: List[Any]) -> List[Any]:
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

        # — Generate human-readable report —————————————————————————————————————
        report_writer = ReportWriter()
        report_path = await loop.run_in_executor(
            None,
            functools.partial(
                report_writer.generate_report,
                file_id=file_id,
                filename=file_metadata.original_filename,
                events_parsed=len(parsed_events),
                events_normalized=len(event_batch.events),
                tier1_result=tier1_result,
                tier2_result=tier2_result,
                ai_outputs=ai_outputs,
                incidents=all_incidents,
                events=enriched_events,
            ),
        )
        logger.info(f"Report saved | path={report_path}")

        # Extract emp_id from current user for JSON report
        user_identity = resolve_user_identity(current_user)
        emp_id = user_identity.get("emp_id")

        incidents_json_path = await loop.run_in_executor(
            None,
            functools.partial(
                report_writer.generate_incident_json_report,
                file_id=file_id,
                filename=file_metadata.original_filename,
                incidents=all_incidents,
                emp_id=emp_id,
                dropped_threats=dropped_threats,
            ),
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
) -> Dict[str, Any]:
    """
    Get accumulated threat intelligence for today.
    Returns day-level view across all 15-minute batches.
    """
    store = get_threat_state_store(date.today())
    return store.get_day_summary()


# Agent outputs endpoint - get actual AI analysis results for Pipeline view
@app.get("/api/v1/agent-outputs/{file_id}", tags=["Analysis"])
async def get_agent_outputs(
    file_id: str,
    _current_user: str = Depends(optional_auth),
) -> Dict[str, Any]:
    """
    Get actual agent analysis outputs for a file.

    Returns aggregated summaries from all 4 AI agents:
    - Behavioral Interpretation
    - Threat Intent
    - MITRE Mapping
    - Triage & Narrative
    """
    storage = get_agent_outputs_storage()
    summary = storage.get_aggregated_summary(file_id)

    return summary


# Rollup Analysis endpoint - long-horizon cross-file correlation
@app.get("/api/v1/rollups", tags=["Analysis"])
async def get_rollup_analysis(
    _current_user: str = Depends(optional_auth),
) -> Dict[str, Any]:
    """
    Get long-horizon rollup analysis across all analyzed files.

    Detects:
    - Low-and-slow attack patterns spanning days/weeks
    - Persistent threat actors across multiple files
    - Cross-file behavioral correlations

    Returns:
        Rollup analysis with actor profiles and risk scores
    """
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
) -> Dict[str, Any]:
    """
    Get reproducibility validation metrics.

    Returns:
        - Cache statistics (hits, misses, hit_rate)
        - Model configuration (name, temperature)
        - Agent statistics
        - Analysis counts
    """
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
    total_agent_errors = 0
    agent_error_counts = {
        "behavioral_interpretation": 0,
        "threat_intent": 0,
        "mitre_mapping": 0,
        "triage": 0,
    }

    for file_id, outputs in all_outputs.items():
        total_analyses += len(outputs)
        for output in outputs:
            total_agent_errors += int(output.get("error_count", 0) or 0)
            for error in output.get("errors", []):
                agent_name = error.get("agent_name")
                if agent_name in agent_error_counts:
                    agent_error_counts[agent_name] += 1
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
            "description": "Same input (chunk hash) → Same output (cached result)",
            "cache_hit_rate": cache_stats.get("hit_rate_percent", 0),
            "total_cache_entries": cache_stats.get("memory_entries", 0),
        },
        "determinism_settings": {
            "temperature": settings.ollama_temperature,
            "max_temperature": 0.2,
            "model": settings.ollama_model,
            "description": "Low temperature (≤0.2) for deterministic outputs",
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
                "errors": agent_error_counts["behavioral_interpretation"],
                "success_rate": 1 if total_behavioral > 0 else 0,
            },
            "intent": {
                "agent": "Threat Intent",
                "invocations": total_intent,
                "errors": agent_error_counts["threat_intent"],
                "success_rate": 1 if total_intent > 0 else 0,
            },
            "mitre": {
                "agent": "MITRE Mapping",
                "invocations": total_mitre,
                "errors": agent_error_counts["mitre_mapping"],
                "success_rate": 1 if total_mitre > 0 else 0,
            },
            "triage": {
                "agent": "Triage & Narrative",
                "invocations": total_triage,
                "errors": agent_error_counts["triage"],
                "success_rate": 1 if total_triage > 0 else 0,
            },
        },
        "total_analyses": total_analyses,
        "total_agent_errors": total_agent_errors,
        "files_analyzed": len(all_outputs),
    }


# — Clear All Data endpoint (for fresh testing) —————————————————————————————————
@app.delete("/api/v1/system/clear-all", tags=["System"])
async def clear_all_data(
    _current_user: str = Depends(optional_auth),
) -> Dict[str, Any]:
    """
    Clear ALL analysis data for fresh testing.
    Wipes: DB tables, raw files, processed files, reports, caches, threat state.
    """
    settings = get_settings()
    cleared = []

    # 1. Clear PostgreSQL tables
    try:
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

    # 4. Clear generated reports (only .md files — preserve source code)
    reports_dir = settings.base_dir / 'reports'
    if reports_dir.exists():
        report_files = list(reports_dir.glob('*_report.md'))
        for f in report_files:
            f.unlink()
        if report_files:
            cleared.append(f'reports ({len(report_files)} files)')

    # 5. Clear analysis cache from memory
    try:
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
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )

   
