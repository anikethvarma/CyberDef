"""
Deterministic Engine

Single-pass scan engine that runs all 61+ rules against event batches.
Tier 1 of the three-tier analysis pipeline.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Optional
from uuid import UUID

from core.logging import get_logger
from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.models import (
    ThreatMatch,
    DeterministicThreat,
    DetectionResult,
    ThreatSeverity,
)
from rules_engine.rules import get_pattern_rules, get_rate_rules
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class DeterministicEngine:
    """
    High-performance deterministic threat detection engine.

    Runs all registered rules against events in a single pass.
    Pattern rules check individual events; rate-based rules
    check grouped events (by src_ip).
    """

    def __init__(self):
        try:
            self.pattern_rules = get_pattern_rules()
            self.rate_rules = get_rate_rules()
            self.scans_completed = 0
            logger.info(
                f"Deterministic engine initialized | pattern_rules={len(self.pattern_rules)}, rate_rules={len(self.rate_rules)}, total_rules={len(self.pattern_rules) + len(self.rate_rules)}"
            )
        except Exception as e:
            logger.error(f"Failed to initialize DeterministicEngine: {e}", exc_info=True)
            raise

    def scan(self, events: list[NormalizedEvent]) -> DetectionResult:
        """
        Scan events with all rules. Returns DetectionResult.

        Phase 1: Run pattern rules on each event (single pass).
        Phase 2: Group events by src_ip, run rate-based rules.
        Phase 3: Group matches into DeterministicThreats.
        """
        try:
            start = time.perf_counter_ns()
            all_matches: list[ThreatMatch] = []

            # Phase 1: Pattern-based rules (single pass over events)
            for event in events:
                for rule in self.pattern_rules:
                    try:
                        match = rule.match(event)
                        if match:
                            all_matches.append(match)
                    except Exception as e:
                        logger.warning(
                            f"Pattern rule '{rule.name}' failed on event {event.event_id}: {e}",
                            exc_info=True,
                        )

            # Phase 1.5: Batch-based rules (full batch context)
            for rule in self.pattern_rules:
                if hasattr(rule, "check_batch"):
                    try:
                        batch_matches = rule.check_batch(events)
                        if batch_matches:
                            all_matches.extend(batch_matches)
                    except Exception as e:
                        logger.warning(
                            f"Batch rule '{rule.name}' failed: {e}",
                            exc_info=True,
                        )

            # Phase 2: Rate-based rules (group by src_ip)
            ip_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
            for event in events:
                if event.src_ip and event.src_ip != "-":
                    ip_groups[event.src_ip].append(event)

            for ip, group_events in ip_groups.items():
                for rule in self.rate_rules:
                    try:
                        match = rule.check_group(group_events, ip)
                        if match:
                            all_matches.append(match)
                    except Exception as e:
                        logger.warning(
                            f"Rate rule '{rule.name}' failed for IP {ip}: {e}",
                            exc_info=True,
                        )

            # Phase 3: Group matches into threats
            threats = self._group_matches(all_matches)

            # Build result
            elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)

            # Compute summaries
            by_category: dict[str, int] = defaultdict(int)
            by_severity: dict[str, int] = defaultdict(int)
            attacker_ips: set[str] = set()
            for threat in threats:
                by_category[threat.category] += 1
                by_severity[threat.severity.value] += 1
                if threat.src_ip:
                    attacker_ips.add(threat.src_ip)
                attacker_ips.update(threat.src_ips)

            # Determine if AI review is needed
            needs_ai, ai_reasons = self._determine_ai_need(events, all_matches, threats)

            result = DetectionResult(
                events_scanned=len(events),
                processing_time_ms=elapsed_ms,
                matches=all_matches[:5000],  # Cap stored matches
                threats=threats,
                threats_by_category=dict(by_category),
                threats_by_severity=dict(by_severity),
                unique_attacker_ips=sorted(attacker_ips),
                needs_ai_review=needs_ai,
                ai_review_reasons=ai_reasons,
            )

            self.scans_completed += 1
            logger.info(
                f"Deterministic scan complete | events={len(events)}, matches={len(all_matches)}, threats={len(threats)}, elapsed_ms={elapsed_ms}, needs_ai={needs_ai}"
            )

            return result
        except Exception as e:
            logger.error(f"Critical failure in DeterministicEngine.scan: {e}", exc_info=True)
            raise

    def _group_matches(self, matches: list[ThreatMatch]) -> list[DeterministicThreat]:
        """Group individual matches into actionable threats by (src_ip, rule_name)."""
        try:
            groups: dict[str, list[ThreatMatch]] = defaultdict(list)
            for m in matches:
                key = f"{m.src_ip or 'unknown'}::{m.rule_name}"
                groups[key].append(m)

            threats = []
            for key, group_matches in groups.items():
                try:
                    first = group_matches[0]

                    # Collect source IPs
                    src_ips = sorted({m.src_ip for m in group_matches if m.src_ip})
                    primary_ip = src_ips[0] if src_ips else None

                    # Time range
                    timestamps = [m.timestamp for m in group_matches if m.timestamp]
                    first_seen = min(timestamps) if timestamps else None
                    last_seen = max(timestamps) if timestamps else None

                    # Sample evidence (unique, up to 5)
                    seen_evidence: set[str] = set()
                    sample_evidence = []
                    for m in group_matches:
                        if m.evidence not in seen_evidence and len(sample_evidence) < 5:
                            sample_evidence.append(m.evidence)
                            seen_evidence.add(m.evidence)

                    threats.append(DeterministicThreat(
                        category=first.category,
                        family=first.family,
                        severity=first.severity,
                        confidence=first.confidence,
                        rule_name=first.rule_name,
                        description=self._get_rule_description(first.rule_name),
                        match_count=len(group_matches),
                        sample_evidence=sample_evidence,
                        affected_event_ids=[m.event_id for m in group_matches[:100]],
                        src_ip=primary_ip,
                        src_ips=src_ips,
                        first_seen=first_seen,
                        last_seen=last_seen,
                    ))
                except Exception as e:
                    logger.warning(f"Failed to group match key '{key}': {e}", exc_info=True)

            # Sort by severity (critical first) then match count
            severity_order = {
                ThreatSeverity.CRITICAL: 0,
                ThreatSeverity.HIGH: 1,
                ThreatSeverity.MEDIUM: 2,
                ThreatSeverity.LOW: 3,
                ThreatSeverity.INFO: 4,
            }
            threats.sort(key=lambda t: (severity_order.get(t.severity, 5), -t.match_count))

            return threats
        except Exception as e:
            logger.error(f"Failed in _group_matches: {e}", exc_info=True)
            return []

    def _get_rule_description(self, rule_name: str) -> str:
        """Look up rule description by name."""
        try:
            for rule in self.pattern_rules + self.rate_rules:
                if rule.name == rule_name:
                    return rule.description
            return f"Threat detected: {rule_name}"
        except Exception as e:
            logger.warning(f"Failed to look up rule description for '{rule_name}': {e}", exc_info=True)
            return f"Threat detected: {rule_name}"

    def _determine_ai_need(
        self,
        events: list[NormalizedEvent],
        matches: list[ThreatMatch],
        threats: list[DeterministicThreat],
    ) -> tuple[bool, list[str]]:
        """Determine if AI escalation is needed."""
        try:
            reasons = []

            # If no threats found but suspicious signals exist
            if not threats:
                # High 4xx rate without specific rule matches
                status_4xx = sum(
                    1 for ev in events
                    if ev.http_status and 400 <= ev.http_status < 500
                )
                if len(events) > 0 and status_4xx / len(events) > 0.3:
                    reasons.append(f"High 4xx rate ({status_4xx}/{len(events)}) without specific rule match")

            # Low-confidence threat — AI can provide context
            low_conf = [t for t in threats if t.confidence < 0.6]
            if low_conf:
                reasons.append(f"{len(low_conf)} low-confidence threats need AI context")

            # Very high match count may indicate coordinated attack
            if len(matches) > 500:
                reasons.append(f"Very high match count ({len(matches)}) — possible coordinated attack")

            return bool(reasons), reasons
        except Exception as e:
            logger.error(f"Failed in _determine_ai_need: {e}", exc_info=True)
            return False, []

    def get_stats(self) -> dict[str, Any]:
        """Get engine statistics."""
        try:
            return {
                "pattern_rules": len(self.pattern_rules),
                "rate_rules": len(self.rate_rules),
                "total_rules": len(self.pattern_rules) + len(self.rate_rules),
                "scans_completed": self.scans_completed,
            }
        except Exception as e:
            logger.error(f"Failed to retrieve engine stats: {e}", exc_info=True)
            return {}

    def scan_parallel(
        self,
        events: list[NormalizedEvent],
        max_workers: int | None = None,
        chunk_size: int = 5000,
    ) -> DetectionResult:
        """
        CPU-parallel pattern scan using ProcessPoolExecutor.

        Phase 1 (pattern rules) is parallelized across CPU cores.
        Phase 2 (rate-based rules) runs single-threaded since it
        requires full IP-group context.

        Falls back to single-threaded for small batches.
        """
        try:
            if len(events) < chunk_size * 2:
                return self.scan(events)

            start = time.perf_counter_ns()
            workers = max_workers or min(os.cpu_count() or 4, 8)

            # Split events into sub-batches for parallel pattern matching
            sub_batches = [
                events[i : i + chunk_size]
                for i in range(0, len(events), chunk_size)
            ]

            logger.info(
                f"Parallel scan starting | events={len(events)}, "
                f"workers={workers}, sub_batches={len(sub_batches)}"
            )

            # Phase 1: Parallel pattern matching
            all_matches: list[ThreatMatch] = []
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = [
                    executor.submit(_worker_pattern_scan, batch)
                    for batch in sub_batches
                ]
                for future in futures:
                    try:
                        all_matches.extend(future.result())
                    except Exception as e:
                        logger.error(f"Worker future failed during parallel scan: {e}", exc_info=True)

            # Phase 1.5: Batch-based rules (full batch context)
            # These must run in the main process as they need the FULL batch,
            # which doesn't fit into the parallel event-chunking model.
            for rule in self.pattern_rules:
                if hasattr(rule, "check_batch"):
                    try:
                        batch_matches = rule.check_batch(events)
                        if batch_matches:
                            all_matches.extend(batch_matches)
                    except Exception as e:
                        logger.warning(
                            f"Batch rule '{rule.name}' failed during parallel scan: {e}",
                            exc_info=True,
                        )

            # Phase 2: Rate-based rules (need full IP grouping — single-threaded)
            ip_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
            for event in events:
                if event.src_ip and event.src_ip != "-":
                    ip_groups[event.src_ip].append(event)

            for ip, group_events in ip_groups.items():
                for rule in self.rate_rules:
                    try:
                        match = rule.check_group(group_events, ip)
                        if match:
                            all_matches.append(match)
                    except Exception as e:
                        logger.warning(
                            f"Rate rule '{rule.name}' failed for IP {ip} during parallel scan: {e}",
                            exc_info=True,
                        )

            # Phase 3: Group matches into threats (reuse existing logic)
            threats = self._group_matches(all_matches)

            elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)

            by_category: dict[str, int] = defaultdict(int)
            by_severity: dict[str, int] = defaultdict(int)
            attacker_ips: set[str] = set()
            for threat in threats:
                by_category[threat.category] += 1
                by_severity[threat.severity.value] += 1
                if threat.src_ip:
                    attacker_ips.add(threat.src_ip)
                attacker_ips.update(threat.src_ips)

            needs_ai, ai_reasons = self._determine_ai_need(events, all_matches, threats)

            result = DetectionResult(
                events_scanned=len(events),
                processing_time_ms=elapsed_ms,
                matches=all_matches[:5000],
                threats=threats,
                threats_by_category=dict(by_category),
                threats_by_severity=dict(by_severity),
                unique_attacker_ips=sorted(attacker_ips),
                needs_ai_review=needs_ai,
                ai_review_reasons=ai_reasons,
            )

            self.scans_completed += 1
            logger.info(
                f"Parallel scan complete | events={len(events)}, "
                f"matches={len(all_matches)}, threats={len(threats)}, "
                f"elapsed_ms={elapsed_ms}"
            )

            return result
        except Exception as e:
            logger.error(f"Critical failure in DeterministicEngine.scan_parallel: {e}", exc_info=True)
            raise


def _worker_pattern_scan(
    events: list[NormalizedEvent],
) -> list[ThreatMatch]:
    """
    Module-level worker for ProcessPoolExecutor.
    Each worker instantiates its own pattern rules and scans its sub-batch.
    """
    try:
        pattern_rules = get_pattern_rules()
        matches = []
        for event in events:
            for rule in pattern_rules:
                try:
                    match = rule.match(event)
                    if match:
                        matches.append(match)
                except Exception as e:
                    # Worker processes cannot use the main logger — use print for subprocess safety
                    print(f"[worker] Rule '{rule.name}' failed on event {event.event_id}: {e}")
        return matches
    except Exception as e:
        print(f"[worker] Critical failure in _worker_pattern_scan: {e}")
        return []
