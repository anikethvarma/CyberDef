"""
Report Writer

Generates human-readable Markdown threat analysis reports with:
- Executive summary
- Threats grouped by source IP across all three tiers
- MITRE ATT&CK mapping table
- SOC-focused mapped raw log evidence
- False-positive confidence indicators
- Day-level statistics
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)

REPORTS_DIR = Path(get_settings().base_dir) / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Report rendering guardrails for very large uploads. Counts remain exact, but
# verbose markdown sections are capped so the API does not stall after analysis.
MAX_ATTACK_MAP_IPS = 500
MAX_DETAIL_IPS = 100
MAX_INCIDENT_ROWS = 500
MAX_RAW_LOG_FALLBACK_EVENTS = 50_000


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "⚪",
    }.get(severity.lower(), "⚪")


def _risk_label(severity: str, confidence: float) -> str:
    """
    Returns a combined risk matrix label used for FP triage hints.
    High severity + low confidence = likely warrants manual review.
    """
    sev = severity.lower()
    if sev in ("critical", "high") and confidence < 0.70:
        return "⚠️ Review Recommended — high severity but lower confidence; verify before blocking"
    if sev in ("critical", "high") and confidence >= 0.85:
        return "✅ High Fidelity — strong confidence, action advised"
    if sev == "medium" and confidence < 0.65:
        return "🔍 Low Signal — possible false positive, correlate with other indicators"
    return "ℹ️ Standard — investigate in normal SOC workflow"


def _activity_window(first_seen: Any, last_seen: Any) -> str | None:
    """
    Compute a human-readable duration between first and last seen timestamps.
    Returns None if either timestamp is missing or unparseable.
    """
    if not first_seen or not last_seen:
        return None
    try:
        fmt = "%Y-%m-%d %H:%M:%S.%f"
        t0 = datetime.strptime(str(first_seen), fmt)
        t1 = datetime.strptime(str(last_seen), fmt)
        delta = t1 - t0
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    except Exception:
        return None


def _group_threats_by_ip(threats: List[Any]) -> Dict[str, List[Any]]:
    """
    Group Tier 1 threat objects by their CANONICAL source IP.
    """
    grouped: Dict[str, List[Any]] = defaultdict(list)
    for threat in threats:
        primary = getattr(threat, "src_ip", None)
        if not primary:
            ips = getattr(threat, "src_ips", []) or []
            primary = ips[0] if ips else "Unknown"
        
        grouped[primary].append(threat)
    return grouped


def _build_t1_attack_map(threats: List[Any]) -> Dict[str, List[Any]]:
    """
    Full fan-out map: every participating IP → all threats it appears in.

    Used ONLY for the Attack Map quick-reference and combined_ips severity
    sort so every IP correctly shows the attacks it was involved in.
    Unlike _group_threats_by_ip this does NOT deduplicate — a multi-IP
    threat will appear under all its src_ips here.
    """
    attack_map: Dict[str, List[Any]] = defaultdict(list)
    for threat in threats:
        ips = getattr(threat, "src_ips", []) or []
        if not ips:
            primary = getattr(threat, "src_ip", None) or "Unknown"
            ips = [primary]
        for ip in ips:
            attack_map[ip].append(threat)
    return attack_map


def _group_patterns_by_ip(patterns: List[Any]) -> Dict[str, List[Any]]:
    """Group Tier 2 correlation patterns by src_ip."""
    grouped: Dict[str, List[Any]] = defaultdict(list)
    for pattern in patterns:
        ip = getattr(pattern, "src_ip", None) or "Unknown"
        grouped[ip].append(pattern)
    return grouped


def _group_ai_by_ip(ai_outputs: List[Any]) -> Dict[str, List[Any]]:
    """Group Tier 3 AI analysis outputs by their src_ip field."""
    grouped: Dict[str, List[Any]] = defaultdict(list)
    for output in ai_outputs:
        ips = _agent_output_ips(output)
        for ip in ips:
            grouped[ip].append(output)
    return grouped


def _agent_output_ips(output: Any) -> List[str]:
    """Extract source IPs from an AgentOutput or its nested triage result."""
    ips = []
    for value in getattr(output, "src_ips", None) or []:
        if _is_present_ip(value):
            ips.append(str(value))

    for value in (
        getattr(output, "src_ip", None),
        getattr(getattr(output, "triage", None), "source_ip", None),
    ):
        if _is_present_ip(value):
            ips.append(str(value))

    return sorted(set(ips)) or ["Unknown"]


def _is_present_ip(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text and text.lower() not in {"-", "null", "none", "unknown"})


def _build_event_index(
    events: List[Any] | None,
    event_ids: Set[str] | None = None,
) -> Dict[str, Any]:
    """Index normalized events by event_id for raw-log lookup."""
    indexed: Dict[str, Any] = {}
    wanted = event_ids or set()
    if event_ids is not None and not wanted:
        return indexed

    for event in events or []:
        event_id = getattr(event, "event_id", None)
        if not event_id:
            continue

        event_id_str = str(event_id)
        if wanted and event_id_str not in wanted:
            continue

        indexed[event_id_str] = event
        if wanted and len(indexed) >= len(wanted):
            break
    return indexed


def _event_urls(event: Any) -> dict:
    """
    Extract URL evidence from a NormalizedEvent using its structured fields only.
    No regex extraction from the raw log string.

    Returns a dict with:
      request_url  - built from http_method + dst_host/dst_ip + url
      referrer     — directly from event.referrer (already a full URL from the parser)
    Either key may be absent if the data is not available.
    """
    urls: dict = {}

    # ── Request URL (structured fields) ──────────────────────────────────
    method   = getattr(event, "http_method", None) or ""
    host     = getattr(event, "dst_host", None) or getattr(event, "dst_ip", None) or ""
    url      = getattr(event, "url", None) or ""


    if url:
        evidence = str(url).strip()
        urls["evidence_path"] = evidence

        req = evidence
        if host and req.startswith("/"):
            req = f"https://{host}{req}"
        if method:
            req = f"{method} {req}"
        urls["request_url"] = req
    # ── Referrer URL (already a full URL stored on the event) ─────────────
    referrer = getattr(event, "referrer", None)
    if referrer and str(referrer).strip() and str(referrer).strip() != "-":
        urls["referrer"] = str(referrer).strip()

    return urls


def _raw_logs_for_threat(
    threat: Any,
    event_by_id: Dict[str, Any],
    limit: int = 5,
    filter_ip: "str | None" = None,
    all_events: "List[Any] | None" = None,
    match_evidence_by_event_id: "Dict[str, str] | None" = None,
) -> list:
    """
    Return (src_ip, urls, raw_log, reason) quadruples for a deterministic threat.

    Each entry carries the src_ip of the event so the render layer can
    group evidence by attacker IP.  If *filter_ip* is given, only events
    whose src_ip matches are included.

    Rate-based rules (flood, brute-force, slowloris …) only store ONE
    event_id (the last triggering event) in affected_event_ids, so the
    ID-based lookup frequently returns nothing.  When that happens and
    *all_events* is provided we fall back to scanning the full event list
    and collecting the first *limit* events whose src_ip matches filter_ip.
    """
    results: list = []
    seen: set = set()

    # ── Primary path: look up by affected_event_ids ──────────────────────
    for event_id in getattr(threat, "affected_event_ids", []) or []:
        event = event_by_id.get(str(event_id))
        if not event:
            continue

        event_ip = getattr(event, "src_ip", None) or "Unknown"

        # Optional IP filter
        if filter_ip is not None:
            if event_ip != filter_ip and event_ip != "Unknown":
                continue

        raw = getattr(event, "original_message", None)
        if not raw:
            continue

        raw_str = str(raw)
        if raw_str and raw_str not in seen:
            urls = _event_urls(event)
            ev_reason = None
            if match_evidence_by_event_id:
                ev_reason = match_evidence_by_event_id.get(str(event_id))
            results.append((event_ip, urls, raw_str, ev_reason))
            seen.add(raw_str)
            if len(results) >= limit:
                break

    # ── Fallback: scan all_events by src_ip when IDs yielded nothing ─────
    # Rate-based rules only embed the LAST event_id, so the above loop
    # often returns 0 results.  Scan the full event list instead.
    if not results and all_events and filter_ip:
        for event in all_events:
            event_ip = getattr(event, "src_ip", None) or "Unknown"
            if event_ip != filter_ip:
                continue

            raw = getattr(event, "original_message", None)
            if not raw:
                continue

            raw_str = str(raw)
            if raw_str and raw_str not in seen:
                urls = _event_urls(event)
                ev_reason = None
                if match_evidence_by_event_id:
                    ev_reason = match_evidence_by_event_id.get(str(getattr(event, "event_id", "")))
                results.append((event_ip, urls, raw_str, ev_reason))
                seen.add(raw_str)
                if len(results) >= limit:
                    break

    return results



# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ReportWriter:
    """Writes human-readable threat analysis reports to the reports/ folder."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        *,
        file_id: str,
        filename: str,
        events_parsed: int,
        events_normalized: int,
        tier1_result: Any,
        tier2_result: Any,
        ai_outputs: List[Any],
        incidents: List[Any],
        events: List[Any] | None = None,
        day_summary: Dict[str, Any] | None = None,
    ) -> Path:
        """Generate and save a complete analysis report. Returns the file path."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = Path(filename).stem.replace(" ", "_")
        report_name = f"{ts}_{file_id}_{safe_name}_report.md"
        report_path = self.reports_dir / report_name

        lines: List[str] = []
        _a = lines.append

        # ── Header ────────────────────────────────────────────────────────────
        _a("# 🛡️ Threat Analysis Report")
        _a("")
        _a("| Field | Value |")
        _a("|-------|-------|")
        _a(f"| **File** | `{filename}` |")
        _a(f"| **File ID** | `{file_id}` |")
        _a(f"| **Generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |")
        _a(f"| **Events Parsed** | {events_parsed:,} |")
        _a(f"| **Events Normalized** | {events_normalized:,} |")
        _a("")

        # ── Executive Summary ─────────────────────────────────────────────────
        threats       = getattr(tier1_result, "threats", [])
        patterns      = getattr(tier2_result, "new_patterns", [])
        
        t1_ips = set()
        for t in threats:
            t1_ips.update(getattr(t, "src_ips", []) or [])
            if getattr(t, "src_ip", None):
                t1_ips.add(getattr(t, "src_ip"))
                
        t2_ips = set()
        for p in patterns:
            ip = getattr(p, "src_ip", None)
            if ip:
                t2_ips.add(ip)
                
        t3_ips = set()
        for o in ai_outputs:
            t3_ips.update(ip for ip in _agent_output_ips(o) if ip != "Unknown")
            
        inc_ips = set()
        for inc in incidents:
            if getattr(inc, "primary_actor_ip", None):
                inc_ips.add(getattr(inc, "primary_actor_ip"))
            inc_ips.update(getattr(inc, "actor_ips", []) or [])

        total_threats = len(threats)
        total_corr    = len(patterns)
        total_ai      = len(ai_outputs)
        total_inc     = len(incidents)

        critical_count = sum(1 for t in threats if t.severity.value == "critical")
        high_count     = sum(1 for t in threats if t.severity.value == "high")

        # Collect all unique attacker IPs across all tiers for summary
        all_ips: Set[str] = t1_ips | t2_ips | t3_ips

        _a("## 📊 Executive Summary")
        _a("")
        if critical_count > 0:
            _a(f"> ⚠️ **CRITICAL**: {critical_count} critical-severity threats detected. Immediate action required.")
        elif high_count > 0:
            _a(f"> ⚡ **HIGH ALERT**: {high_count} high-severity threats detected. Investigation recommended.")
        else:
            _a("> ✅ No critical or high-severity threats detected in this batch.")
        _a("")
        _a("| Metric | Count |")
        _a("|--------|-------|")
        _a(f"| Tier 1 Deterministic Threats | **{total_threats}** |")
        _a(f"| Tier 1 Unique IPs | **{len(t1_ips)}** |")
        _a(f"| Tier 2 Correlation Findings | **{total_corr}** |")
        _a(f"| Tier 2 Unique IPs | **{len(t2_ips)}** |")
        _a(f"| Tier 3 AI Analyses (chunks) | **{total_ai}** |")
        _a(f"| Tier 3 Unique IPs (AI-reviewed) | **{len(t3_ips)}** |")
        _a(f"| Total Incidents Created | **{total_inc}** |")
        _a(f"| Unique IPs Represented in Incidents | **{len(inc_ips)}** |")
        _a(f"| Unique Attacker IPs (all tiers) | **{len(all_ips)}** |")
        _a("")
        _a("> ℹ️ **Note:** Tier 3 AI Analyses counts *behavioral chunks* (one IP may produce")
        _a("> multiple chunks across time windows). Internal/Zscaler IPs are excluded from")
        _a("> AI escalation, so Tier 3 IP count may be lower than Tier 1+2 unique IP totals.")

        # ── IP Attack Map (quick-reference) ──────────────────────────────────
        _a("---")
        _a("## 🗺️ Attacker IP — Attack Map")
        _a("")
        _a("Quick-reference overview of every detected attacker and their attack surface.")
        _a("")

        t1_by_ip    = _group_threats_by_ip(threats)   # canonical: 1 threat → 1 IP (Tier 1 detail)
        t1_attack_map = _build_t1_attack_map(threats)  # fan-out:   1 threat → all src_ips (Attack Map)
        t2_by_ip    = _group_patterns_by_ip(patterns)
        t3_by_ip    = _group_ai_by_ip(ai_outputs)
        affected_event_ids = {
            str(event_id)
            for threat in threats
            for event_id in (getattr(threat, "affected_event_ids", []) or [])
        }
        event_by_id = _build_event_index(events, affected_event_ids)
        raw_log_fallback_events = (
            events
            if events and len(events) <= MAX_RAW_LOG_FALLBACK_EVENTS
            else None
        )
        match_evidence_by_event_id = {
            str(match.event_id): match.evidence
            for match in (getattr(tier1_result, "matches", []) or [])
        }

        combined_ips = sorted(
            all_ips,
            key=lambda ip: (
                -max(
                    ({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                        t.severity.value, 0) for t in t1_attack_map.get(ip, [])),
                    default=0,
                )
            ),
        )

        attack_map_ips = combined_ips[:MAX_ATTACK_MAP_IPS]
        omitted_attack_map_ips = len(combined_ips) - len(attack_map_ips)
        if omitted_attack_map_ips > 0:
            _a(f"_Showing first {len(attack_map_ips):,} IPs; {omitted_attack_map_ips:,} additional IPs omitted from report detail._")
            _a("")

        for ip in attack_map_ips:
            threats_for_ip = set()

            # Tier 1 Threats
            for t in t1_attack_map.get(ip, []):
                threats_for_ip.add(
                    f"{_severity_emoji(t.severity.value)} "
                    f"{t.rule_name.replace('_', ' ').title()}"
                )

            # Tier 2 Correlation Findings
            for p in t2_by_ip.get(ip, []):
                threats_for_ip.add(
                    f"🔗 {p.correlation_rule.replace('_', ' ').title()}"
                )

            # Tier 3 AI Intent Mapping
            for o in t3_by_ip.get(ip, []):
                intent = getattr(getattr(o, "intent", None), "suspected_intent", None)
                if intent:
                    threats_for_ip.add(f"🤖 {intent}")

            mapped_threats = " | ".join(sorted(threats_for_ip))

            if mapped_threats:
                _a(f"- `{ip}` → {mapped_threats}")

        # ── Tier 1: Deterministic Threats grouped by IP ───────────────────────
        _a("---")
        _a("## 🔍 Tier 1: Deterministic Threat Detections")
        _a("")
        _a("> Threats are grouped by source IP. Each IP section opens with an inline")
        _a("> attack summary followed by detailed findings and raw evidence for SOC review.")
        _a("")

        if threats:
            tier1_detail_ips = sorted(
                t1_by_ip.keys(),
                key=lambda ip: (
                    -max(
                        ({"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                            t.severity.value, 0) for t in t1_by_ip.get(ip, [])),
                        default=0,
                    )
                ),
            )[:MAX_DETAIL_IPS]
            omitted_detail_ips = len(t1_by_ip) - len(tier1_detail_ips)
            if omitted_detail_ips > 0:
                _a(f"_Showing first {len(tier1_detail_ips):,} source IP sections; {omitted_detail_ips:,} additional sections omitted._")
                _a("")

            for ip in tier1_detail_ips:
                ip_threats = t1_by_ip.get(ip, [])

                if not ip_threats:
                    continue

                # Sort by severity descending
                sev_order = {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 3,
                    "info": 4,
                }

                ip_threats = sorted(
                    ip_threats,
                    key=lambda t: sev_order.get(t.severity.value, 99)
                )

                # Remove duplicate threat labels
                seen_labels = set()
                attack_labels = []

                for t in ip_threats:
                    label = (
                        f"{_severity_emoji(t.severity.value)} "
                        f"{t.rule_name.replace('_', ' ').title()}"
                    )

                    if label not in seen_labels:
                        attack_labels.append(label)
                        seen_labels.add(label)

                # Get all unique usernames across all threats for this IP
                all_usernames = set()
                for t in ip_threats:
                    all_usernames.update(getattr(t, "usernames", []) or [])
                usernames_str = ", ".join(sorted(all_usernames)) if all_usernames else ""

                if usernames_str:
                    _a(f"### 🖥️ Source IP: `{ip}` | User IDs: `{usernames_str}`")
                else:
                    _a(f"### 🖥️ Source IP: `{ip}`")
                _a("")
                _a(f"**Attacks detected:** {' | '.join(attack_labels)}")
                _a("")

                for i, threat in enumerate(ip_threats, 1):

                    sev_e = _severity_emoji(threat.severity.value)
                    conf = threat.confidence
                    window = _activity_window(
                        threat.first_seen,
                        threat.last_seen
                    )

                    _a(
                        f"#### {sev_e} {i}. "
                        f"{threat.rule_name.replace('_', ' ').title()}"
                    )

                    _a("")
                    _a("| Property | Detail |")
                    _a("|----------|--------|")
                    _a(f"| **Severity** | {threat.severity.value.upper()} |")
                    _a(f"| **Confidence** | {conf:.0%} |")

                    _a(
                        f"| **FP Risk Assessment** | "
                        f"{_risk_label(threat.severity.value, conf)} |"
                    )

                    _a(
                        f"| **Category** | "
                        f"{threat.category.replace('_', ' ').title()} |"
                    )

                    _a(f"| **Family** | {threat.family} |")
                    _a(f"| **Match Count** | {threat.match_count} |")
                    _a(f"| **Source IP** | {ip} |")
                    
                    if getattr(threat, "usernames", None):
                        _a(f"| **User IDs** | {', '.join(threat.usernames)} |")



                    if threat.first_seen:
                        _a(f"| **First Seen** | {threat.first_seen} |")

                    if threat.last_seen:
                        _a(f"| **Last Seen** | {threat.last_seen} |")

                    if window:
                        _a(f"| **Activity Window** | {window} |")

                    _a("")
                    _a(f"**Description:** {threat.description}")
                    _a("")

                    if getattr(threat, "sample_evidence", None):
                        _a("**Rule Evidence:**")
                        _a("")
                        for ev in threat.sample_evidence:
                            _a(f"- {ev}")
                        _a("")

                    mapped_raw_logs = _raw_logs_for_threat(
                        threat,
                        event_by_id,
                        filter_ip=ip,
                        all_events=raw_log_fallback_events,
                        match_evidence_by_event_id=match_evidence_by_event_id,
                    )

                    if mapped_raw_logs:
                        _a("**Evidence & Raw Logs (SOC Review):**")
                        _a("")

                        for idx, (_, urls, raw, ev_reason) in enumerate(mapped_raw_logs, 1):
                            _a(f"**📎 Evidence #{idx}:**")
                            _a("")

                            if urls.get("request_url") or urls.get("referrer") or urls.get("evidence_path") or ev_reason:
                                _a("| Field | Value |")
                                _a("|-------|-------|")

                                if urls.get("evidence_path"):
                                    _a(
                                        f"| **Evidence Path** | "
                                        f"`{urls['evidence_path']}` |"
                                    )

                                if urls.get("request_url"):
                                    _a(
                                        f"| **Request URL** | "
                                        f"`{urls['request_url']}` |"
                                    )

                                if urls.get("referrer"):
                                    _a(
                                        f"| **Referrer** | "
                                        f"`{urls['referrer']}` |"
                                    )

                                if ev_reason:
                                    _a(
                                        f"| **Reason/Evidence** | "
                                        f"`{ev_reason}` |"
                                    )

                                _a("")
                            else:
                                _a("_No URL or reason evidence available for this log entry._")
                                _a("")

                            _a(f"**📋 Raw Log #{idx}:**")
                            _a("")
                            _a("```")
                            _a(raw[:1000])
                            _a("```")
                            _a("")

                    _a(
                        f"**Recommendation:** "
                        f"{self._get_recommendation(threat.category, threat.severity.value)}"
                    )
                    _a("")
                    _a("---")
                    _a("")
        else:
            _a("No deterministic threats detected.")
            _a("")

        # ── Tier 2: Correlation Findings grouped by IP ────────────────────────
        _a("## 🔗 Tier 2: Cross-Batch Correlation Findings")
        _a("")
        _a("> Correlation findings reveal persistent or multi-vector attacker behaviour")
        _a("> observed across multiple events or batches, grouped by source IP.")
        _a("")

        if patterns:
            tier2_detail_ips = sorted(t2_by_ip.keys())[:MAX_DETAIL_IPS]
            omitted_tier2_ips = len(t2_by_ip) - len(tier2_detail_ips)
            if omitted_tier2_ips > 0:
                _a(f"_Showing first {len(tier2_detail_ips):,} correlation IP sections; {omitted_tier2_ips:,} additional sections omitted._")
                _a("")

            for ip in tier2_detail_ips:
                ip_patterns = t2_by_ip.get(ip, [])
                if not ip_patterns:
                    continue

                pattern_labels = " | ".join(
                    p.correlation_rule.replace("_", " ").title()
                    for p in ip_patterns
                )

                _a(f"### 🖥️ Source IP: `{ip}`")
                _a("")
                _a(f"**Correlation rules fired:** {pattern_labels}")
                _a("")

                for i, pattern in enumerate(ip_patterns, 1):
                    _a(f"#### {i}. {pattern.correlation_rule.replace('_', ' ').title()}")
                    _a("")
                    _a("| Property | Detail |")
                    _a("|----------|--------|")
                    _a(f"| **Severity** | {pattern.severity.upper()} |")
                    _a(f"| **Confidence** | {pattern.confidence:.0%} |")
                    _a(f"| **Source IP** | {pattern.src_ip} |")
                    _a("")
                    _a(f"**Description:** {pattern.description}")
                    _a("")

                    if pattern.evidence:
                        _a("**Correlation Evidence:**")
                        _a("")
                        for k, v in pattern.evidence.items():
                            _a(f"- **{k}**: `{v}`")
                        _a("")

                    _a("---")
                    _a("")
        else:
            _a("No new correlation patterns detected.")
            _a("")

        # ── Tier 3: AI Analysis grouped by IP ────────────────────────────────
        _a("## 🤖 Tier 3: AI Agent Analysis")
        _a("")
        _a("> AI analyses are grouped by source IP. Each block includes behavioural")
        _a("> assessment, intent mapping, MITRE ATT&CK technique, and triage narrative.")
        _a("")

        if ai_outputs:
            tier3_detail_ips = sorted(t3_by_ip.keys())[:MAX_DETAIL_IPS]
            omitted_tier3_ips = len(t3_by_ip) - len(tier3_detail_ips)
            if omitted_tier3_ips > 0:
                _a(f"_Showing first {len(tier3_detail_ips):,} AI IP sections; {omitted_tier3_ips:,} additional sections omitted._")
                _a("")

            for ip in tier3_detail_ips:
                ip_outputs = t3_by_ip.get(ip, [])
                if not ip_outputs:
                    continue

                intent_labels = " | ".join(
                    getattr(getattr(o, "intent", None), "suspected_intent", "Unknown intent")
                    for o in ip_outputs
                )

                _a(f"### 🖥️ Source IP: `{ip}`")
                _a("")
                _a(f"**Suspected intent(s):** {intent_labels}")
                _a("")

                for i, output in enumerate(ip_outputs, 1):
                    _a(f"#### AI Analysis #{i}")
                    _a("")

                    # Behavioural
                    if hasattr(output, "behavioral") and output.behavioral:
                        b = output.behavioral
                        _a(f"**Behavioural Assessment:** {'🚨 Suspicious' if b.is_suspicious else '✅ Normal'}")
                        _a("")
                        _a("| Field | Detail |")
                        _a("|-------|--------|")
                        _a(f"| **Interpretation** | {b.interpretation} |")
                        _a(f"| **Confidence** | {b.confidence:.0%} |")
                        _a(f"| **FP Risk Assessment** | {_risk_label('high' if b.is_suspicious else 'low', b.confidence)} |")
                        if b.reasoning:
                            _a(f"| **Reasoning** | {b.reasoning} |")
                        _a("")
                        if b.key_indicators:
                            _a("**Key Indicators:**")
                            for ki in b.key_indicators[:5]:
                                _a(f"- `{ki}`")
                            _a("")

                    # Intent
                    if hasattr(output, "intent") and output.intent:
                        it = output.intent
                        _a("**Threat Intent:**")
                        _a("")
                        _a("| Field | Detail |")
                        _a("|-------|--------|")
                        _a(f"| **Suspected Intent** | {it.suspected_intent} |")
                        _a(f"| **Kill Chain Stage** | {it.kill_chain_stage.value} |")
                        _a(f"| **Confidence** | {it.confidence:.0%} |")
                        if it.reasoning:
                            _a(f"| **Reasoning** | {it.reasoning} |")
                        _a("")
                        if it.alternative_intents:
                            _a(f"**Alternative Intents (consider for FP review):** {', '.join(it.alternative_intents[:3])}")
                            _a("")

                    # MITRE
                    if hasattr(output, "mitre") and output.mitre:
                        m = output.mitre
                        _a("**MITRE ATT&CK Mapping:**")
                        _a("")
                        _a("| Technique ID | Name | Tactic | Confidence |")
                        _a("|-------------|------|--------|------------|")
                        _a(f"| {m.technique_id} | {m.technique_name} | {m.tactic} | {m.confidence:.0%} |")
                        for rt in (m.related_techniques or [])[:3]:
                            _a(f"| {rt.get('technique_id', 'N/A')} | {rt.get('technique_name', 'N/A')} | {rt.get('tactic', 'N/A')} | Related |")
                        _a("")
                        if m.justification:
                            _a(f"**Justification:** {m.justification}")
                            _a("")

                    # Triage
                    if hasattr(output, "triage") and output.triage:
                        tr = output.triage
                        priority_val = tr.priority.value if hasattr(tr.priority, "value") else tr.priority
                        _a("**Triage & Narrative:**")
                        _a("")
                        _a("| Field | Detail |")
                        _a("|-------|--------|")
                        _a(f"| **Priority** | **{priority_val}** |")
                        _a(f"| **Risk** | {tr.risk_reason} |")
                        _a(f"| **Recommended Action** | {tr.recommended_action} |")
                        if tr.executive_summary:
                            _a(f"| **Executive Summary** | {tr.executive_summary} |")
                        if tr.technical_summary:
                            _a(f"| **Technical Details** | {tr.technical_summary} |")
                        _a("")
                        if tr.enrichment_suggestions:
                            _a("**Further Investigation (SOC):**")
                            for sug in tr.enrichment_suggestions:
                                _a(f"- {sug}")
                            _a("")

                    _a("---")
                    _a("")
        else:
            _a("AI analysis was not triggered for this batch (deterministic coverage sufficient).")
            _a("")

        # ── MITRE ATT&CK Summary ─────────────────────────────────────────────
        _a("## 🎯 MITRE ATT&CK Coverage Summary")
        _a("")
        mitre_seen: Set[str] = set()
        mitre_rows: List[str] = []
        for output in ai_outputs:
            if hasattr(output, "mitre") and output.mitre:
                m = output.mitre
                if m.technique_id not in mitre_seen:
                    mitre_seen.add(m.technique_id)
                    mitre_rows.append(
                        f"| {m.technique_id} | {m.technique_name} | {m.tactic} "
                        f"| {getattr(output, 'src_ip', 'N/A')} | {m.confidence:.0%} |"
                    )
                for rt in (m.related_techniques or []):
                    rt_id = rt.get("technique_id", "")
                    if rt_id and rt_id not in mitre_seen:
                        mitre_seen.add(rt_id)
                        mitre_rows.append(
                            f"| {rt_id} | {rt.get('technique_name', 'N/A')} "
                            f"| {rt.get('tactic', 'N/A')} | {getattr(output, 'src_ip', 'N/A')} | Related |"
                        )
        if mitre_rows:
            _a("| Technique ID | Name | Tactic | Source IP | Confidence |")
            _a("|-------------|------|--------|-----------|------------|")
            for row in mitre_rows:
                _a(row)
            _a("")
        else:
            _a("No MITRE ATT&CK techniques mapped in this analysis.")
            _a("")



        # ── Incidents Summary ─────────────────────────────────────────────────
        _a("---")
        _a("## 🚨 Incidents Created")
        _a("")
        if incidents:
            _a("| # | ID | Title | Priority | Status | Tier | IP | UserID |")
            _a("|---|-----|-------|----------|--------|------|----|--------|")
            incident_rows_to_render = incidents[:MAX_INCIDENT_ROWS]
            omitted_incidents = len(incidents) - len(incident_rows_to_render)
            if omitted_incidents > 0:
                _a(f"_Showing first {len(incident_rows_to_render):,} incidents; {omitted_incidents:,} additional incidents omitted from markdown summary._")
            for i, inc in enumerate(incident_rows_to_render, 1):
                title          = getattr(inc, "title", "Unknown")
                priority       = getattr(inc, "priority", "unknown")
                incident_status = getattr(inc, "status", "open")
                tier           = getattr(inc, "detection_tier", None)
                if not tier:
                    source_enum = getattr(inc, "source", "unknown")
                    tier = str(source_enum).replace("IncidentSource.", "").title()
                inc_id         = str(getattr(inc, "incident_id", ""))[:8]
                ip             = getattr(inc, "primary_actor_ip", None) or getattr(inc, "source_ip", "Unknown")
                userid         = getattr(inc, "primary_actor_username", None) or getattr(inc, "source_username", "N/A")
                _a(f"| {i} | `{inc_id}…` | {title} | **{priority}** | {incident_status} | {tier} | {ip} | {userid} |")
            _a("")
        else:
            _a("No incidents created from this analysis.")
            _a("")

        # ── Overall Recommendations ───────────────────────────────────────────
        _a("---")
        _a("## 📋 Overall Recommendations")
        _a("")
        recommendations = self._get_overall_recommendations(threats, patterns)
        for i, rec in enumerate(recommendations, 1):
            _a(f"{i}. {rec}")
        _a("")

        # ── Footer ────────────────────────────────────────────────────────────
        _a("---")
        _a("*Report generated by mPulse Threat Analysis Engine v1.0*")
        _a(f"*Report path: `{report_path}`*")
        _a("")

        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(
            f"Threat report generated | path={report_path}, lines={len(lines)}"
        )
        return report_path

    # -------------------------------------------------------------------------
    # Incident JSON report  (unchanged from original)
    # -------------------------------------------------------------------------

    def generate_incident_json_report(
        self,
        *,
        file_id: str,
        filename: str,
        incidents: List[Any],
        emp_id: Optional[str] = None,
        dropped_threats: Optional[List[Dict[str, Any]]] = None,
    ) -> Path:
        """Generate a machine-readable incident JSON report for a file."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = Path(filename).stem.replace(" ", "_")
        report_name = f"{ts}_{file_id}_{safe_name}_incidents.json"
        report_path = self.reports_dir / report_name

        incident_rows = [self._incident_to_json(incident) for incident in incidents]
        normalized_dropped = dropped_threats or []
        payload = {
            "MI_ID": "GenAI_SOC",
            "file_id": file_id,
            "filename": filename,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "incident_count": len(incident_rows),
            "dropped_count": len(normalized_dropped),
            "emp_id": emp_id,
            "incidents": incident_rows,
            "dropped_threats": [
                {
                    "tier": d.get("tier"),
                    "rule": d.get("rule"),
                    "source_ip": d.get("source_ip"),
                    "severity": d.get("severity"),
                    "confidence": d.get("confidence"),
                    "llm_drop_remark": d.get("llm_drop_remark"),
                }
                for d in normalized_dropped
            ],
        }

        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info(
            f"Incident JSON report generated | path={report_path}, "
            f"incidents={len(incident_rows)}, emp_id={emp_id}"
        )
        return report_path

    def _incident_to_json(self, incident: Any) -> Dict[str, Any]:
        """Convert an incident model into the required report JSON shape."""
        data: Dict[str, Any]
        if hasattr(incident, "model_dump"):
            data = incident.model_dump(mode="json")
        elif isinstance(incident, dict):
            data = incident
        else:
            data = {}

        confidence = float(data.get("overall_confidence", 0.0) or 0.0)
        confidence_score = data.get("confidence_score")
        if confidence_score is None:
            confidence_score = max(1, min(10, int(round(confidence * 10))))

        mitre_techniques = data.get("mitre_techniques") or []
        top_mitre = mitre_techniques[0] if mitre_techniques else {}

        source_ip = data.get("source_ip") or data.get("primary_actor_ip")
        source_username = data.get("source_username") or data.get("primary_actor_username")

        destination_ip = data.get("destination_ip")
        if not destination_ip:
            affected_hosts = data.get("affected_hosts", [])
            if affected_hosts:
                destination_ip = affected_hosts[0]

        hostname = None
        if destination_ip:
            hostname = destination_ip
        elif data.get("affected_hosts"):
            hostname = data.get("affected_hosts")[0]

        raw_log = data.get("raw_log", "")

        correlation_context = {
            "signature_attacks": [],
            "src_ip": source_ip,
            "dst_ip": destination_ip,
            "hostname": hostname,
            "raw_logs": [raw_log] if raw_log else [],
            "correlation_reason": self._build_correlation_reason(data),
        }

        if data.get("detection_rule"):
            correlation_context["signature_attacks"].append(data.get("detection_rule"))
        if data.get("attack_name"):
            correlation_context["signature_attacks"].append(data.get("attack_name"))
        for tech in mitre_techniques:
            if isinstance(tech, dict) and tech.get("technique_name"):
                correlation_context["signature_attacks"].append(tech.get("technique_name"))

        return {
            "incident_id": data.get("incident_id"),
            "tier": data.get("detection_tier") or str(data.get("source", "")).replace("IncidentSource.", "").title(),
            "title": data.get("title"),
            "status": data.get("status"),
            "priority": data.get("priority"),
            "file_ids": data.get("file_ids", []),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "raw_log": raw_log,
            "source_ip": source_ip,
            "source_username": source_username,
            "destination_ip": destination_ip,
            "hostname": hostname,
            "suspicious": data.get("suspicious", True),
            "suspicious_indicator": data.get("suspicious_indicator"),
            "attack_name": data.get("attack_name") or data.get("detection_rule") or data.get("title"),
            "brief_description": data.get("brief_description") or data.get("executive_summary") or data.get("description"),
            "recommended_action": data.get("recommended_action") or (data.get("recommended_actions") or [""])[0],
            "confidence_score": confidence_score,
            "mitre_tactic": data.get("mitre_tactic") or data.get("primary_tactic") or top_mitre.get("tactic"),
            "mitre_technique": data.get("mitre_technique") or top_mitre.get("technique_id"),
            "correlation": correlation_context,
        }

    def _build_correlation_reason(self, data: Dict[str, Any]) -> str:
        """Build a strong reason for correlation based on incident data."""
        reasons = []
        detection_tier = data.get("detection_tier", "unknown")
        source = data.get("source", "unknown")

        if detection_tier == "correlation":
            reasons.append(
                f"Cross-batch correlation detected via {data.get('detection_rule', 'unknown rule')}"
            )
        elif detection_tier == "deterministic":
            reasons.append(f"Deterministic rule match: {data.get('detection_rule', 'unknown')}")
        elif source == "AI_DETECTION":
            reasons.append("AI-based behavioral analysis detected suspicious activity")

        mitre_tactic = data.get("mitre_tactic") or data.get("primary_tactic")
        mitre_technique = data.get("mitre_technique")
        if mitre_tactic and mitre_technique:
            reasons.append(f"MITRE ATT&CK: {mitre_tactic} - {mitre_technique}")

        attack_categories = data.get("attack_categories_seen", [])
        if attack_categories:
            reasons.append(f"Attack categories: {', '.join(attack_categories[:3])}")

        confidence = data.get("overall_confidence", 0.0)
        priority = data.get("priority", "unknown")
        if confidence >= 0.8:
            reasons.append(f"High confidence detection ({confidence:.2f})")
        if priority in ["CRITICAL", "HIGH"]:
            reasons.append(f"{priority} priority incident")

        return (
            " | ".join(reasons) if reasons else "Incident detected through automated analysis"
        )

    # -------------------------------------------------------------------------
    # Recommendation helpers  (unchanged from original)
    # -------------------------------------------------------------------------

    def _get_recommendation(self, category: str, severity: str) -> str:
        recs = {
            "sql_injection": "Immediately review the affected endpoints. Implement parameterized queries and input validation. Deploy WAF rules to block SQL injection patterns.",
            "blind_sql_injection": "Treat as high-risk SQLi probing. Add database query timeout limits and block time-based injection signatures at WAF and application layers.",
            "cross_site_scripting": "Sanitize all user inputs with context-aware output encoding. Implement Content Security Policy (CSP) headers.",
            "os_command_injection": "CRITICAL: Block the source IP immediately. Audit the affected application for command injection vectors. Use allowlists for shell command parameters.",
            "path_traversal": "Validate and sanitize all file path inputs. Use chroot jails or containerization. Restrict file system permissions.",
            "local_file_inclusion": "Sanitize all include/require parameters. Use allowlists for includable files. Disable remote file inclusion.",
            "remote_code_execution": "CRITICAL: Isolate the affected system immediately. Patch the vulnerable software. Conduct forensic analysis.",
            "server_side_template_injection": "Sanitize template inputs. Use sandbox mode for template engines. Restrict template functions.",
            "broken_authentication": "Implement account lockout after failed attempts. Enable MFA. Review password policies.",
            "authentication_failures": "Investigate repeated login failures, tune auth telemetry, and enforce progressive lockout or challenge policies.",
            "sensitive_information_disclosure": "Review error handling to suppress stack traces. Audit HTTP headers for information leaks.",
            "rate_limiting": "Implement rate limiting per IP. Deploy DDoS protection. Consider CAPTCHA for automated request patterns.",
            "rate_limiting_bypass": "Harden trust boundaries for forwarding headers, enforce per-identity + per-IP quotas, and validate upstream proxy chains.",
            "recon_scanner": "Monitor for follow-up exploitation attempts. Consider IP reputation blocking. Update IDS/IPS signatures.",
            "hardcoded_credentials": "Rotate all potentially exposed credentials immediately. Use secrets management (Vault, AWS Secrets Manager).",
            "hardcoded_credential_exposure": "Rotate all potentially exposed credentials immediately. Use secrets management (Vault, AWS Secrets Manager).",
            "cache_deception": "Implement cache key validation. Disable caching for sensitive endpoints. Add Cache-Control headers.",
            "http_flood": "Enable rate limiting and connection throttling. Deploy anti-DDoS solution.",
        }
        return recs.get(
            category,
            "Investigate the source IP and affected endpoints. Review application logs for additional context.",
        )

    def _get_overall_recommendations(self, threats: list, correlations: list) -> List[str]:
        recs = []
        categories = set()
        for t in threats:
            categories.add(t.category)
            if t.severity.value == "critical":
                recs.append(
                    f"🔴 **CRITICAL**: Block source IP(s) {', '.join(t.src_ips)} immediately "
                    f"and investigate {t.rule_name.replace('_', ' ')} activity."
                )
        if any(c in categories for c in ["sql_injection", "os_command_injection", "remote_code_execution"]):
            recs.append(
                "Deploy Web Application Firewall (WAF) with active blocking for injection patterns."
            )
        if any(
            c in categories
            for c in ["broken_authentication", "authentication_failures", "hardcoded_credentials", "hardcoded_credential_exposure"]
        ):
            recs.append(
                "Audit authentication mechanisms and rotate any potentially compromised credentials."
            )
        if "recon_scanner" in categories or "bot_automation" in categories:
            recs.append(
                "Review perimeter security. Consider IP reputation lists and automated scanner blocking."
            )
        if correlations:
            recs.append(
                "Cross-batch patterns detected — persistent threat actors. Escalate to SOC for extended monitoring."
            )
        if not recs:
            recs.append("No critical actions required. Continue standard monitoring.")
        recs.append("Review this report and update incident response playbooks as needed.")
        return recs
