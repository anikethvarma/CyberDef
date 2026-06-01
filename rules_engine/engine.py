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
from typing import Any

from core.ip_filter import get_zscaler_source_ips
from core.logging import get_logger
from .models import (
    DeterministicThreat,
    ThreatMatch,
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

    ZSCALER_EXCLUDED_RULES = {
        "brute_force_login",
        "rapid_404_generation",
        "content_scraping",
        "slowloris_suspected",
        "open_redirect",
        "waf_bypass",
        "http_param_pollution",
    }

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

    def scan(self, events: list[NormalizedEvent]) -> Any:
        """
        Scan events with all rules. Returns DetectionResult.

        Phase 1: Run pattern rules on each event (single pass).
        Phase 2: Group events by src_ip, run rate-based rules.
        Phase 3: Group matches into DeterministicThreats.
        """
        from .models import DetectionResult
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

            # Phase 2: Rate-based rules (group by Actor: Username if present, else src_ip)
            actor_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
            for event in events:
                # Use canonical identity: Username if present, else src_ip
                actor = event.username if (event.username and event.username not in ("-", "null", "None", "unknown")) else event.src_ip
                if actor and actor != "-":
                    actor_groups[actor].append(event)

            for actor, group_events in actor_groups.items():
                for rule in self.rate_rules:
                    try:
                        match = rule.check_group(group_events, actor)
                        if match:
                            all_matches.append(match)
                    except Exception as e:
                        logger.warning(
                            f"Rate rule '{rule.name}' failed for Actor {actor}: {e}",
                            exc_info=True,
                        )

            all_matches = self._filter_zscaler_excluded_matches(all_matches)

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
                # Group by rule_name only — do NOT include src_ip.
                # Rate-based identity-aware rules (e.g. USER_ENDPOINT_FLOODING) group
                # events by actor (username), so src_ip can differ across matches for
                # the same threat. Grouping by src_ip would collapse unrelated actors
                # (same IP, different users) OR split the same actor (same user, diff IPs).
                key = m.aggregation_key or m.rule_name
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

    def _filter_zscaler_excluded_matches(
        self,
        matches: list[ThreatMatch],
    ) -> list[ThreatMatch]:
        """Drop selected deterministic matches after detection when src_ip is Zscaler."""
        try:
            candidate_ips = [
                match.src_ip
                for match in matches
                if match.src_ip
                and match.rule_name.split(":", 1)[0] in self.ZSCALER_EXCLUDED_RULES
            ]
            zscaler_src_ips = get_zscaler_source_ips(candidate_ips)
            if not zscaler_src_ips:
                return matches

            filtered = [
                match
                for match in matches
                if not (
                    match.rule_name.split(":", 1)[0] in self.ZSCALER_EXCLUDED_RULES
                    and match.src_ip in zscaler_src_ips
                )
            ]
            excluded_count = len(matches) - len(filtered)
            if excluded_count:
                logger.info(
                    f"Zscaler post-detection filter applied | excluded_matches={excluded_count}, "
                    f"zscaler_src_ips={len(zscaler_src_ips)}"
                )
            return filtered
        except Exception as e:
            logger.warning(f"Failed to apply Zscaler post-detection filter: {e}", exc_info=True)
            return matches

    def _get_rule_description(self, rule_name: str) -> str:
        """Look up rule description by name."""
        try:
            for rule in self.pattern_rules + self.rate_rules:
                if rule.name == rule_name:
                    return rule.description
                if rule_name.startswith(f"{rule.name}:"):
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
        """Determine if AI escalation is needed.

        Always escalates when any deterministic threats or rule matches exist so
        that every Tier 1 finding gets AI analysis.  Falls back to heuristic
        signal checks when the batch produced no threats at all.
        """
        try:
            reasons = []

            # Always escalate if any threats were detected
            if threats:
                reasons.append(
                    f"{len(threats)} deterministic threat(s) detected — escalating all to AI"
                )
                return True, reasons

            # Always escalate if any rule matches fired (even without grouped threats)
            if matches:
                reasons.append(
                    f"{len(matches)} rule match(es) detected — escalating all to AI"
                )
                return True, reasons

            # Fallback: no threats/matches but suspicious signal in the batch
            status_4xx = sum(
                1 for ev in events
                if ev.http_status and 400 <= ev.http_status < 500
            )
            if len(events) > 0 and status_4xx / len(events) > 0.3:
                reasons.append(
                    f"High 4xx rate ({status_4xx}/{len(events)}) without specific rule match"
                )

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
    ) -> Any:
        """
        CPU-parallel pattern scan using ProcessPoolExecutor.
        """
        from .models import DetectionResult
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

            # Phase 2: Rate-based rules (need full Actor grouping — single-threaded)
            actor_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
            for event in events:
                actor = event.username if (event.username and event.username not in ("-", "null", "None", "unknown")) else event.src_ip
                if actor and actor != "-":
                    actor_groups[actor].append(event)

            for actor, group_events in actor_groups.items():
                for rule in self.rate_rules:
                    try:
                        match = rule.check_group(group_events, actor)
                        if match:
                            all_matches.append(match)
                    except Exception as e:
                        logger.warning(
                            f"Rate rule '{rule.name}' failed for Actor {actor} during parallel scan: {e}",
                            exc_info=True,
                        )

            all_matches = self._filter_zscaler_excluded_matches(all_matches)

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
