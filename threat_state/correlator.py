"""
Day-Level Correlator

Tier 2: Cross-batch correlation rules that detect threats invisible in
single 15-minute windows. Uses the Threat State Store accumulated data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from core.logging import get_logger
from threat_state.store import ThreatStateStore, ActorState

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

    def correlate(self) -> CorrelationResult:
        """Run all correlation rules and return new findings."""
        import time
        start = time.perf_counter_ns()

        all_findings: list[CorrelationFinding] = []

        for actor in self.store.actors.values():
            # Run each correlation rule
            all_findings.extend(self._check_low_slow_brute_force(actor))
            all_findings.extend(self._check_distributed_recon(actor))
            all_findings.extend(self._check_multi_vector(actor))
            all_findings.extend(self._check_kill_chain(actor))
            all_findings.extend(self._check_scanner_persistence(actor))
            all_findings.extend(self._check_rate_acceleration(actor))
            all_findings.extend(self._check_off_hours(actor))
            all_findings.extend(self._check_data_exfil(actor))


        # Filter to only NEW findings (not previously reported)
        new = []
        for f in all_findings:
            key = f"{f.src_ip}::{f.correlation_rule}"
            if key not in self._previously_reported:
                self._previously_reported.add(key)
                new.append(f)

        elapsed_ms = int((time.perf_counter_ns() - start) / 1_000_000)

        needs_ai = False
        ai_reasons = []
        # Escalate kill-chain or multi-vector actors
        for f in new:
            if f.correlation_rule in ("kill_chain_progression", "multi_vector_attacker"):
                needs_ai = True
                ai_reasons.append(f"{f.correlation_rule}: {f.src_ip}")

        return CorrelationResult(
            findings=all_findings,
            new_patterns=new,
            processing_time_ms=elapsed_ms,
            needs_ai_review=needs_ai,
            ai_review_reasons=ai_reasons,
        )

    # â”€â”€ C1: Low-and-slow brute force â”€â”€
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

    # â”€â”€ C2: Distributed reconnaissance â”€â”€
    def _check_distributed_recon(self, actor: ActorState) -> list[CorrelationFinding]:
        if actor.unique_uris_accessed >= 200 and actor.batches_seen_in >= 2:
            return [CorrelationFinding(
                correlation_rule="distributed_recon",
                category="recon_scanner",
                severity="high",
                confidence=0.8,
                description=f"Distributed recon: {actor.unique_uris_accessed} unique URIs across {actor.batches_seen_in} batches",
                src_ip=actor.ip,
                evidence={"unique_uris": actor.unique_uris_accessed},
            )]
        return []

    # â”€â”€ C3: Multi-vector attacker â”€â”€
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

    # â”€â”€ C4: Kill-chain progression â”€â”€
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
            stage = "recon â†’ exploit"
            if has_post:
                stage += " â†’ post-exploitation"
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

    # â”€â”€ C5: Scanner persistence â”€â”€
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

    # â”€â”€ C6: Rate acceleration â”€â”€
    def _check_rate_acceleration(self, actor: ActorState) -> list[CorrelationFinding]:
        history = actor.request_rate_history
        if len(history) >= 3:
            rates = [h["count"] for h in history[-3:]]
            if rates[-1] >= 2 * rates[0] and rates[-1] > 50:
                return [CorrelationFinding(
                    correlation_rule="rate_acceleration",
                    category="rate_limiting",
                    severity="medium",
                    confidence=0.7,
                    description=f"Rate acceleration: {rates[0]} â†’ {rates[-1]} requests across last 3 batches",
                    src_ip=actor.ip,
                    evidence={"rates": rates},
                )]
        return []

    # â”€â”€ C7: Off-hours anomaly â”€â”€
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

    # ── C8: Data exfiltration pattern ──
    def _check_data_exfil(self, actor: ActorState) -> list[CorrelationFinding]:
        import ipaddress
        
        # Check if IP is public (interpreting dstip check against the actor's public address)
        try:
            is_public = not ipaddress.ip_address(actor.ip).is_private
        except ValueError:
            is_public = False
            
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
