from __future__ import annotations

"""
Day-Level Correlator

Tier 2: Cross-batch correlation rules that detect threats invisible in
single 15-minute windows. Uses the Threat State Store accumulated data.
"""

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from core.logging import get_logger
from core.ip_filter import is_ip_excluded
from threat_state.store import ActorState, ThreatStateStore
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class CorrelationFinding(BaseModel):
    """A single cross-batch correlation finding."""
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_rule: str
    category: str
    severity: str  # critical, high, medium
    confidence: float
    description: str
    src_ip: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    detection_tier: str = "correlation"


class CorrelationResult(BaseModel):
    """Result from Tier 2 day-level correlation."""
    findings: list[CorrelationFinding] = Field(default_factory=list)
    new_patterns: list[CorrelationFinding] = Field(default_factory=list)
    processing_time_ms: int = 0
    needs_ai_review: bool = False
    ai_review_reasons: list[str] = Field(default_factory=list)


class DayLevelCorrelator:
    """
    Runs 9 cross-batch correlation rules against the Threat State Store.
    Called after every Tier 1 scan to detect patterns spanning multiple batches.
    """

    def __init__(self, store: ThreatStateStore):
        self.store = store
        self._previously_reported: set[str] = set()

    def correlate(self, events: list[NormalizedEvent] | None = None) -> CorrelationResult:
        """Run all correlation rules and return new findings."""
        import time
        start = time.perf_counter_ns()

        all_findings: list[CorrelationFinding] = []

        for actor in self.store.actors.values():
            # Run each correlation rule
            all_findings.extend(self._check_low_slow_brute_force(actor))

            all_findings.extend(self._check_multi_vector(actor))
            all_findings.extend(self._check_kill_chain(actor))
            all_findings.extend(self._check_scanner_persistence(actor))
            all_findings.extend(self._check_rate_acceleration(actor))
            all_findings.extend(self._check_off_hours(actor))
            all_findings.extend(self._check_data_exfil(actor))

        if events:
            all_findings.extend(self._check_distributed_recon(events))


        # Filter to only NEW findings (not previously reported)
        new = []
        for f in all_findings:
            key = f"{f.src_ip}::{f.correlation_rule}"
            if key not in self._previously_reported:
                self._previously_reported.add(key)
                new.append(f)

        elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)

        # Always escalate every new correlation finding to AI — not just
        # kill_chain and multi_vector — so all Tier 2 findings get AI analysis.
        needs_ai = bool(new)
        ai_reasons = [f"{f.correlation_rule}: {f.src_ip}" for f in new]

        return CorrelationResult(
            findings=all_findings,
            new_patterns=new,
            processing_time_ms=elapsed_ms,
            needs_ai_review=needs_ai,
            ai_review_reasons=ai_reasons,
        )

    # -- C1: Low-and-slow brute force --
    def _check_low_slow_brute_force(self, actor: ActorState) -> list[CorrelationFinding]:
        if actor.auth_failures_total >= 50:
            return [CorrelationFinding(
                correlation_rule="low_slow_brute_force",
                category="broken_authentication",
                severity="high",
                confidence=0.85,
                description=f"Low-and-slow brute force: {actor.auth_failures_total} auth failures across {actor.batches_seen_in} batches",
                src_ip=actor.ip,
                evidence={"auth_failures": actor.auth_failures_total, "batches": actor.batches_seen_in},
            )]
        return []

    # -- C2: Distributed reconnaissance --
    def _check_distributed_recon(self, events: list[NormalizedEvent]) -> list[CorrelationFinding]:
        findings = []
        from collections import defaultdict

        def get_actor(ev: NormalizedEvent) -> str:
            if ev.username:
                return ev.username
            return f"{ev.src_ip or 'unknown'}_{ev.user_agent or 'unknown'}"

        # 1. Detect distributed pattern
        actors = set()
        unique_uris = set()
        total_requests = len(events)
        
        for ev in events:
            actors.add(get_actor(ev))
            if ev.uri_path:
                unique_uris.add(ev.uri_path)

        total_actors = len(actors)
        total_unique_uris = len(unique_uris)
        avg_requests = total_requests / total_actors if total_actors > 0 else 0

        if total_actors >= 15 and total_unique_uris >= 50 and avg_requests <= 5:
            # 2. Per-actor analysis
            actor_requests = defaultdict(int)
            actor_uris = defaultdict(set)
            actor_ips = defaultdict(set)
            
            for ev in events:
                act = get_actor(ev)
                actor_requests[act] += 1
                if ev.uri_path:
                    actor_uris[act].add(ev.uri_path)
                if ev.src_ip:
                    actor_ips[act].add(ev.src_ip)

            for act in actors:
                reqs = actor_requests[act]
                uris_count = len(actor_uris[act])
                ratio = uris_count / reqs if reqs > 0 else 0

                if reqs >= 20 and uris_count >= 15 and ratio >= 0.7:
                    sample_uri = list(actor_uris[act])[0] if actor_uris[act] else "unknown"
                    sample_ip = list(actor_ips[act])[0] if actor_ips[act] else "unknown"
                    
                    findings.append(CorrelationFinding(
                        correlation_rule="distributed_recon",
                        category="recon_scanner",
                        severity="high",
                        confidence=0.85,
                        description=(
                            f"DISTRIBUTED_RECON : "
                            f"actor={act} | "
                            f"src_ip={sample_ip} | "
                            f"URIs={uris_count} | "
                            f"Total={reqs} | "
                            f"Ratio={ratio:.2f} | "
                            f"Sample={sample_uri}"
                        ),
                        src_ip=sample_ip,
                        evidence={"actor": act, "campaign_uris": total_unique_uris, "actor_ratio": ratio},
                    ))
        return findings

    # -- C3: Multi-vector attacker --
    def _check_multi_vector(self, actor: ActorState) -> list[CorrelationFinding]:
        if len(actor.attack_categories_seen) >= 3:
            return [CorrelationFinding(
                correlation_rule="multi_vector_attacker",
                category="multi_vector_attack",
                severity="critical",
                confidence=0.9,
                description=f"Multi-vector: {len(actor.attack_categories_seen)} attack types ({', '.join(actor.attack_categories_seen[:5])})",
                src_ip=actor.ip,
                evidence={"categories": actor.attack_categories_seen},
            )]
        return []

    # -- C4: Kill-chain progression --
    def _check_kill_chain(self, actor: ActorState) -> list[CorrelationFinding]:
        recon_cats = {"recon_scanner", "bot_automation"}
        exploit_cats = {"sql_injection", "cross_site_scripting", "os_command_injection",
                        "path_traversal", "lfi", "local_file_inclusion", "rfi", "remote_code_execution",
                        "server_side_template_injection", "cve_exploit"}
        post_exploit = {"sensitive_information_disclosure", "hardcoded_credentials", "hardcoded_credential_exposure",
                        "arbitrary_file_read"}

        cats = set(actor.attack_categories_seen)
        has_recon = bool(cats & recon_cats)
        has_exploit = bool(cats & exploit_cats)
        has_post = bool(cats & post_exploit)

        if has_recon and has_exploit:
            stage = "recon -> exploit"
            if has_post:
                stage += " -> post-exploitation"
            return [CorrelationFinding(
                correlation_rule="kill_chain_progression",
                category="kill_chain",
                severity="critical",
                confidence=0.9,
                description=f"Kill-chain: {stage}",
                src_ip=actor.ip,
                evidence={"stages": stage, "categories": actor.attack_categories_seen},
            )]
        return []

    # -- C5: Scanner persistence --
    def _check_scanner_persistence(self, actor: ActorState) -> list[CorrelationFinding]:
        scanner_uas = ["sqlmap", "nikto", "nuclei", "dirbuster", "gobuster",
                       "wfuzz", "ffuf", "burp", "nmap", "acunetix", "nessus"]
        persistent_scanners = [
            ua for ua in actor.user_agents_seen
            if any(s in ua.lower() for s in scanner_uas)
        ]
        if persistent_scanners and actor.batches_seen_in >= 3:
            return [CorrelationFinding(
                correlation_rule="scanner_persistence",
                category="recon_scanner",
                severity="high",
                confidence=0.9,
                description=f"Scanner persists across {actor.batches_seen_in} batches",
                src_ip=actor.ip,
                evidence={"scanner_uas": persistent_scanners[:3]},
            )]
        return []

    # -- C6: Rate acceleration --
    def _check_rate_acceleration(self, actor: ActorState) -> list[CorrelationFinding]:
        """Detect rate acceleration across the last three time windows."""
        # Only check public IPs and configured custom exclusions.
        if is_ip_excluded(actor.ip):
            return []

        history = actor.request_rate_history
        if len(history) < 3:
            return []

        # Get last 3 windows (most recent = W3, oldest = W1)
        W1 = history[-3]["count"]  # 45-30min ago
        W2 = history[-2]["count"]  # 30-15min ago
        W3 = history[-1]["count"]  # 15min-now

        # Check for consistent upward trend
        if W3 <= W2 or W2 <= W1:
            return []

        # Calculate metrics
        increase1 = W2 - W1
        increase2 = W3 - W2
        acceleration = increase2 - increase1
        growth_rate = ((W3 - W2) / W2) * 100 if W2 > 0 else 0

        # Apply thresholds
        if W3 >= 500 and acceleration >= 200 and growth_rate >= 80:
            return [CorrelationFinding(
                correlation_rule="rate_acceleration",
                category="rate_limiting",
                severity="high",
                confidence=0.85,
                description=(
                    f"Rate acceleration detected: {W1} -> {W2} -> {W3} requests | "
                    f"acceleration={acceleration:.0f} | growth_rate={growth_rate:.1f}%"
                ),
                src_ip=actor.ip,
                evidence={
                    "W1": W1,
                    "W2": W2,
                    "W3": W3,
                    "increase1": increase1,
                    "increase2": increase2,
                    "acceleration": acceleration,
                    "growth_rate": growth_rate,
                },
            )]
        return []


    # -- C7: Off-hours anomaly --
    def _check_off_hours(self, actor: ActorState) -> list[CorrelationFinding]:
        off_hours_attacks = 0
        for entry in actor.attack_timeline:
            try:
                hour = int(entry.timestamp[11:13])
                if 0 <= hour < 6:  # Midnight to 6 AM
                    off_hours_attacks += 1
            except (ValueError, IndexError):
                pass
        if off_hours_attacks >= 5:
            return [CorrelationFinding(
                correlation_rule="off_hours_anomaly",
                category="suspicious_timing",
                severity="medium",
                confidence=0.6,
                description=f"{off_hours_attacks} attack events during off-hours (00:00-06:00)",
                src_ip=actor.ip,
                evidence={"off_hours_count": off_hours_attacks},
            )]
        return []

    # -- C8: Data exfiltration pattern --
    def _check_data_exfil(self, actor: ActorState) -> list[CorrelationFinding]:
        import ipaddress

        # Check if IP is public (uses centralized IP filter with custom exclusions)
        is_public = not is_ip_excluded(actor.ip)

        large_200_count = int(actor.requests_by_status.get("200", 0))

        # Enforce thresholds without checking attack_categories_seen
        if is_public and large_200_count > 100 and actor.total_requests > 200:
            success_ratio = large_200_count / actor.total_requests
            if success_ratio > 0.5 and actor.threat_score > 0.3:
                return [CorrelationFinding(
                    correlation_rule="data_exfiltration_pattern",
                    category="data_exfiltration",
                    severity="high",
                    confidence=0.6,
                    description=f"Potential data exfil: Public IP actor with {large_200_count} successful requests",
                    src_ip=actor.ip,
                    evidence={"success_count": large_200_count, "threat_score": actor.threat_score},
                )]
        return []
