"""
Report Writer

Generates human-readable Markdown threat analysis reports with:
- Executive summary
- Detailed threat breakdown with verbiage
- MITRE ATT&CK mapping table
- Recommendations per threat
- Day-level statistics
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.config import get_settings
from core.logging import get_logger

logger = get_logger(__name__)

REPORTS_DIR = Path(get_settings().base_dir) / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportWriter:
    """Writes human-readable threat analysis reports to the reports/ folder."""

    def __init__(self, reports_dir: Path | None = None):
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
        ai_outputs: list[Any],
        incidents: list[Any],
        day_summary: dict[str, Any] | None = None,
    ) -> Path:
        """Generate and save a complete analysis report. Returns the file path."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = Path(filename).stem.replace(" ", "_")
        # Include file_id in the report filename so it can be fetched reliably later.
        report_name = f"{ts}_{file_id}_{safe_name}_report.md"
        report_path = self.reports_dir / report_name

        lines: list[str] = []
        _a = lines.append

        # â”€â”€ Header
        _a("# ðŸ›¡ï¸ Threat Analysis Report")
        _a("")
        _a("| Field | Value |")
        _a("|-------|-------|")
        _a(f"| **File** | `{filename}` |")
        _a(f"| **File ID** | `{file_id}` |")
        _a(f"| **Generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |")
        _a(f"| **Events Parsed** | {events_parsed:,} |")
        _a(f"| **Events Normalized** | {events_normalized:,} |")
        _a("")

        # â”€â”€ Executive Summary
        total_threats = len(getattr(tier1_result, 'threats', []))
        total_correlations = len(getattr(tier2_result, 'new_patterns', []))
        total_ai = len(ai_outputs)
        total_incidents = len(incidents)

        critical_count = sum(
            1 for t in getattr(tier1_result, 'threats', [])
            if t.severity.value == 'critical'
        )
        high_count = sum(
            1 for t in getattr(tier1_result, 'threats', [])
            if t.severity.value == 'high'
        )

        _a("## ðŸ“Š Executive Summary")
        _a("")
        if critical_count > 0:
            _a(f"> âš ï¸ **CRITICAL**: {critical_count} critical-severity threats detected. Immediate action required.")
        elif high_count > 0:
            _a(f"> âš¡ **HIGH ALERT**: {high_count} high-severity threats detected. Investigation recommended.")
        else:
            _a("> âœ… No critical or high-severity threats detected in this batch.")
        _a("")
        _a("| Metric | Count |")
        _a("|--------|-------|")
        _a(f"| Tier 1 Deterministic Threats | **{total_threats}** |")
        _a(f"| Tier 2 Correlation Findings | **{total_correlations}** |")
        _a(f"| Tier 3 AI Analyses | **{total_ai}** |")
        _a(f"| Total Incidents Created | **{total_incidents}** |")
        _a(f"| Unique Attacker IPs | **{len(getattr(tier1_result, 'unique_attacker_ips', []))}** |")
        _a("")

        # â”€â”€ Tier 1: Deterministic Threats
        _a("---")
        _a("## ðŸ” Tier 1: Deterministic Threat Detections")
        _a("")
        threats = getattr(tier1_result, 'threats', [])
        if threats:
            for i, threat in enumerate(threats, 1):
                severity_emoji = {
                    'critical': 'ðŸ”´', 'high': 'ðŸŸ ', 'medium': 'ðŸŸ¡', 'low': 'ðŸŸ¢', 'info': 'âšª'
                }.get(threat.severity.value, 'âšª')

                _a(f"### {severity_emoji} {i}. {threat.rule_name.replace('_', ' ').title()}")
                _a("")
                _a("| Property | Detail |")
                _a("|----------|--------|")
                _a(f"| **Severity** | {threat.severity.value.upper()} |")
                _a(f"| **Confidence** | {threat.confidence:.0%} |")
                _a(f"| **Category** | {threat.category.replace('_', ' ').title()} |")
                _a(f"| **Family** | {threat.family} |")
                _a(f"| **Match Count** | {threat.match_count} |")
                _a(f"| **Source IP(s)** | {', '.join(threat.src_ips) if threat.src_ips else 'N/A'} |")
                if threat.first_seen:
                    _a(f"| **First Seen** | {threat.first_seen} |")
                if threat.last_seen:
                    _a(f"| **Last Seen** | {threat.last_seen} |")
                _a("")
                _a(f"**Description:** {threat.description}")
                _a("")
                if threat.sample_evidence:
                    _a("**Sample Evidence:**")
                    for ev in threat.sample_evidence[:3]:
                        _a(f"- `{ev[:200]}`")
                    _a("")
                _a(f"**Recommendation:** {self._get_recommendation(threat.category, threat.severity.value)}")
                _a("")
        else:
            _a("No deterministic threats detected.")
            _a("")

        # â”€â”€ Tier 2: Correlation Findings
        _a("---")
        _a("## ðŸ”— Tier 2: Cross-Batch Correlation Findings")
        _a("")
        patterns = getattr(tier2_result, 'new_patterns', [])
        if patterns:
            for i, pattern in enumerate(patterns, 1):
                _a(f"### {i}. {pattern.correlation_rule.replace('_', ' ').title()}")
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
                    _a("**Evidence:**")
                    for k, v in pattern.evidence.items():
                        _a(f"- **{k}**: {v}")
                    _a("")
        else:
            _a("No new correlation patterns detected.")
            _a("")

        # â”€â”€ Tier 3: AI Analysis
        _a("---")
        _a("## ðŸ¤– Tier 3: AI Agent Analysis")
        _a("")
        if ai_outputs:
            for i, output in enumerate(ai_outputs, 1):
                _a(f"### AI Analysis #{i}")
                _a("")
                if hasattr(output, 'behavioral') and output.behavioral:
                    b = output.behavioral
                    _a(f"**Behavioral Assessment:** {'ðŸš¨ Suspicious' if b.is_suspicious else 'âœ… Normal'}")
                    _a(f"- Interpretation: {b.interpretation}")
                    _a(f"- Confidence: {b.confidence:.0%}")
                    if b.reasoning:
                        _a(f"- Reasoning: {b.reasoning}")
                    if b.key_indicators:
                        _a(f"- Key Indicators: {', '.join(b.key_indicators[:5])}")
                    _a("")
                if hasattr(output, 'intent') and output.intent:
                    it = output.intent
                    _a("**Threat Intent:**")
                    _a(f"- Suspected Intent: {it.suspected_intent}")
                    _a(f"- Kill Chain Stage: {it.kill_chain_stage.value}")
                    _a(f"- Confidence: {it.confidence:.0%}")
                    if it.reasoning:
                        _a(f"- Reasoning: {it.reasoning}")
                    if it.alternative_intents:
                        _a(f"- Alternative Intents: {', '.join(it.alternative_intents[:3])}")
                    _a("")
                if hasattr(output, 'mitre') and output.mitre:
                    m = output.mitre
                    _a("**MITRE ATT&CK Mapping:**")
                    _a("")
                    _a("| Technique ID | Name | Tactic | Confidence |")
                    _a("|-------------|------|--------|------------|")
                    _a(f"| {m.technique_id} | {m.technique_name} | {m.tactic} | {m.confidence:.0%} |")
                    if m.related_techniques:
                        for rt in m.related_techniques[:3]:
                            _a(f"| {rt.get('technique_id', 'N/A')} | {rt.get('technique_name', 'N/A')} | {rt.get('tactic', 'N/A')} | Related |")
                    _a("")
                    if m.justification:
                        _a(f"**Justification:** {m.justification}")
                        _a("")
                if hasattr(output, 'triage') and output.triage:
                    tr = output.triage
                    _a("**Triage & Narrative:**")
                    _a(f"- Priority: **{tr.priority.value if hasattr(tr.priority, 'value') else tr.priority}**")
                    _a(f"- Risk: {tr.risk_reason}")
                    _a(f"- Recommended Action: {tr.recommended_action}")
                    if tr.executive_summary:
                        _a(f"- Executive Summary: {tr.executive_summary}")
                    if tr.technical_summary:
                        _a(f"- Technical Details: {tr.technical_summary}")
                    if tr.enrichment_suggestions:
                        _a("")
                        _a("**Further Investigation:**")
                        for sug in tr.enrichment_suggestions:
                            _a(f"- {sug}")
                    _a("")
                _a("---")
                _a("")
        else:
            _a("AI analysis was not triggered for this batch (deterministic coverage sufficient).")
            _a("")

        # â”€â”€ MITRE ATT&CK Summary Table
        _a("## ðŸŽ¯ MITRE ATT&CK Coverage Summary")
        _a("")
        # Collect all MITRE mappings (each output has one MitreMapping, not a list)
        mitre_seen: set[str] = set()
        mitre_rows: list[str] = []
        for output in ai_outputs:
            if hasattr(output, 'mitre') and output.mitre:
                m = output.mitre
                if m.technique_id not in mitre_seen:
                    mitre_seen.add(m.technique_id)
                    mitre_rows.append(f"| {m.technique_id} | {m.technique_name} | {m.tactic} | {m.confidence:.0%} |")
                for rt in (m.related_techniques or []):
                    rt_id = rt.get('technique_id', '')
                    if rt_id and rt_id not in mitre_seen:
                        mitre_seen.add(rt_id)
                        mitre_rows.append(f"| {rt_id} | {rt.get('technique_name', 'N/A')} | {rt.get('tactic', 'N/A')} | Related |")
        if mitre_rows:
            _a("| Technique ID | Name | Tactic | Confidence |")
            _a("|-------------|------|--------|------------|")
            for row in mitre_rows:
                _a(row)
            _a("")
        else:
            _a("No MITRE ATT&CK techniques mapped in this analysis.")
            _a("")

        # â”€â”€ Incidents Summary
        _a("---")
        _a("## ðŸš¨ Incidents Created")
        _a("")
        if incidents:
            _a("| # | ID | Title | Priority | Status | Source |")
            _a("|---|-----|-------|----------|--------|--------|")
            for i, inc in enumerate(incidents, 1):
                title = getattr(inc, 'title', 'Unknown')
                priority = getattr(inc, 'priority', 'unknown')
                incident_status = getattr(inc, 'status', 'open')
                source = getattr(inc, 'source', 'unknown')
                inc_id = str(getattr(inc, 'incident_id', ''))[:8]
                _a(f"| {i} | `{inc_id}â€¦` | {title} | **{priority}** | {incident_status} | {source} |")
            _a("")
        else:
            _a("No incidents created from this analysis.")
            _a("")

        # â”€â”€ Recommendations
        _a("---")
        _a("## ðŸ“‹ Overall Recommendations")
        _a("")
        recommendations = self._get_overall_recommendations(threats, patterns)
        for i, rec in enumerate(recommendations, 1):
            _a(f"{i}. {rec}")
        _a("")

        # â”€â”€ Footer
        _a("---")
        _a("*Report generated by CyberDef Threat Analysis Engine v1.0*")
        _a(f"*Report path: `{report_path}`*")
        _a("")

        report_path.write_text("\n".join(lines), encoding="utf-8")
        logger.info(f"Threat report generated | path={report_path}, lines={len(lines)}")
        return report_path

    def generate_incident_json_report(
        self,
        *,
        file_id: str,
        filename: str,
        incidents: list[Any],
        emp_id: str | None = None,
    ) -> Path:
        """Generate a machine-readable incident JSON report for a file."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_name = Path(filename).stem.replace(" ", "_")
        report_name = f"{ts}_{file_id}_{safe_name}_incidents.json"
        report_path = self.reports_dir / report_name

        incident_rows = [self._incident_to_json(incident) for incident in incidents]
        payload = {
            "MI_ID": "GenAI_SOC",  # Static key-value pair
            "file_id": file_id,
            "filename": filename,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "incident_count": len(incident_rows),
            "emp_id": emp_id,  # Employee ID from authentication context
            "incidents": incident_rows,
        }

        report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info(f"Incident JSON report generated | path={report_path}, incidents={len(incident_rows)}, emp_id={emp_id}")
        return report_path

    def _incident_to_json(self, incident: Any) -> dict[str, Any]:
        """Convert an incident model into the required report JSON shape."""
        data: dict[str, Any]
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
        
        # Extract source IP (primary actor)
        source_ip = data.get("source_ip") or data.get("primary_actor_ip")
        
        # Extract destination IP (affected host)
        destination_ip = data.get("destination_ip")
        if not destination_ip:
            affected_hosts = data.get("affected_hosts", [])
            if affected_hosts:
                destination_ip = affected_hosts[0]
        
        # Extract hostname from destination or affected hosts
        hostname = None
        if destination_ip:
            hostname = destination_ip
        elif data.get("affected_hosts"):
            hostname = data.get("affected_hosts")[0]
        
        # Extract raw log for correlation analysis
        raw_log = data.get("raw_log", "")
        
        # Build correlation context with proper signature attacks, IPs, hostname, and raw logs
        correlation_context = {
            "signature_attacks": [],
            "src_ip": source_ip,
            "dst_ip": destination_ip,
            "hostname": hostname,
            "raw_logs": [raw_log] if raw_log else [],
            "correlation_reason": self._build_correlation_reason(data),
        }
        
        # Extract signature attacks from detection rule and MITRE techniques
        if data.get("detection_rule"):
            correlation_context["signature_attacks"].append(data.get("detection_rule"))
        if data.get("attack_name"):
            correlation_context["signature_attacks"].append(data.get("attack_name"))
        for tech in mitre_techniques:
            if isinstance(tech, dict) and tech.get("technique_name"):
                correlation_context["signature_attacks"].append(tech.get("technique_name"))

        return {
            "incident_id": data.get("incident_id"),
            "title": data.get("title"),
            "status": data.get("status"),
            "priority": data.get("priority"),
            "file_ids": data.get("file_ids", []),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "raw_log": raw_log,
            "source_ip": source_ip,
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
    
    def _build_correlation_reason(self, data: dict[str, Any]) -> str:
        """Build a strong reason for correlation based on incident data."""
        reasons = []
        
        # Detection tier and source
        detection_tier = data.get("detection_tier", "unknown")
        source = data.get("source", "unknown")
        
        if detection_tier == "correlation":
            reasons.append(f"Cross-batch correlation detected via {data.get('detection_rule', 'unknown rule')}")
        elif detection_tier == "deterministic":
            reasons.append(f"Deterministic rule match: {data.get('detection_rule', 'unknown')}")
        elif source == "AI_DETECTION":
            reasons.append("AI-based behavioral analysis detected suspicious activity")
        
        # MITRE ATT&CK context
        mitre_tactic = data.get("mitre_tactic") or data.get("primary_tactic")
        mitre_technique = data.get("mitre_technique")
        if mitre_tactic and mitre_technique:
            reasons.append(f"MITRE ATT&CK: {mitre_tactic} - {mitre_technique}")
        
        # Attack patterns
        attack_categories = data.get("attack_categories_seen", [])
        if attack_categories:
            reasons.append(f"Attack categories: {', '.join(attack_categories[:3])}")
        
        # Confidence and priority
        confidence = data.get("overall_confidence", 0.0)
        priority = data.get("priority", "unknown")
        if confidence >= 0.8:
            reasons.append(f"High confidence detection ({confidence:.2f})")
        if priority in ["CRITICAL", "HIGH"]:
            reasons.append(f"{priority} priority incident")
        
        return " | ".join(reasons) if reasons else "Incident detected through automated analysis"

    def _get_recommendation(self, category: str, severity: str) -> str:
        """Get specific recommendation based on threat category."""
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
        return recs.get(category, "Investigate the source IP and affected endpoints. Review application logs for additional context.")

    def _get_overall_recommendations(self, threats: list, correlations: list) -> list[str]:
        """Generate overall recommendations based on all findings."""
        recs = []
        categories = set()
        for t in threats:
            categories.add(t.category)
            if t.severity.value == 'critical':
                recs.append(f"ðŸ”´ **CRITICAL**: Block source IP(s) {', '.join(t.src_ips)} immediately and investigate {t.rule_name.replace('_', ' ')} activity.")
        if any(c in categories for c in ['sql_injection', 'os_command_injection', 'remote_code_execution']):
            recs.append("Deploy Web Application Firewall (WAF) with active blocking for injection patterns.")
        if any(c in categories for c in ['broken_authentication', 'authentication_failures', 'hardcoded_credentials', 'hardcoded_credential_exposure']):
            recs.append("Audit authentication mechanisms and rotate any potentially compromised credentials.")
        if 'recon_scanner' in categories or 'bot_automation' in categories:
            recs.append("Review perimeter security. Consider IP reputation lists and automated scanner blocking.")
        if correlations:
            recs.append("Cross-batch patterns detected â€” persistent threat actors. Escalate to SOC for extended monitoring.")
        if not recs:
            recs.append("No critical actions required. Continue standard monitoring.")
        recs.append("Review this report and update incident response playbooks as needed.")
        return recs


