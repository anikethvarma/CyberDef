"""
Incident Service

Manages incidents by grouping and tracking agent outputs.
Now includes JSON file persistence to survive backend restarts.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.config import get_settings
from core.logging import get_logger
from rules_engine.models import DeterministicThreat
from shared_models.agents import AgentOutput
from shared_models.chunks import BehavioralChunk
from shared_models.incidents import (
    Incident,
    IncidentPriority,
    IncidentReport,
    IncidentSource,
    IncidentStatus,
    IncidentSummary,
    IncidentTimeline,
    MitreReference,
)

logger = get_logger(__name__)

# Persistence file path
_INCIDENTS_FILE: Optional[Path] = None

def _get_incidents_file() -> Path:
    """Get the incidents JSON file path."""
    global _INCIDENTS_FILE
    if _INCIDENTS_FILE is None:
        settings = get_settings()
        _INCIDENTS_FILE = settings.processed_dir / "incidents_data.json"
        _INCIDENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    return _INCIDENTS_FILE


MitreGuess = Tuple[str, str, str, float, str]

# Deterministic fallback MITRE mappings for Tier 1/Tier 2 findings.
# Format: rule/category/family -> (technique_id, technique_name, tactic, confidence, justification)
_RULE_MITRE_MAP: Dict[str, MitreGuess] = {
    # Injection / exploit-like detections
    "sql_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.82, "Rule indicates web application exploitation behavior."),
    "blind_sql_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.82, "Rule indicates web application exploitation behavior."),
    "os_command_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.84, "Command injection attempts map to public-facing exploit activity."),
    "xss": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.7, "Cross-site scripting indicates abuse of exposed application functionality."),
    "ssti": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Template injection indicates server-side application exploitation."),
    "xxe": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "XML external entity abuse indicates app-layer exploit attempts."),
    "ldap_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.76, "LDAP injection indicates app-layer exploit attempts."),
    "xpath_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.76, "XPath injection indicates app-layer exploit attempts."),
    "ssrf": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.78, "Server-side request forgery indicates exploit of server-side logic."),
    "insecure_deserialization": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.78, "Deserialization abuse indicates exploit behavior."),
    "expression_language_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Expression language injection indicates exploit behavior."),
    "prototype_pollution": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.7, "Prototype pollution indicates application abuse."),
    "path_traversal": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Traversal indicators imply exploitation of input handling."),
    "local_file_inclusion": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Local file inclusion indicates web exploit attempts."),
    "remote_file_inclusion": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.82, "Remote file inclusion indicates web exploit attempts."),
    "arbitrary_file_read": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Arbitrary file read indicates exploit behavior."),
    "webshell_access": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.86, "Webshell access indicates prior compromise via exposed app."),
    "log4shell_cve_2021_44228": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9, "CVE exploitation of public-facing services."),
    "spring4shell_cve_2022_22965": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9, "CVE exploitation of public-facing services."),
    "shellshock_cve_2014_6271": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9, "CVE exploitation of public-facing services."),
    "apache_struts_rce": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.9, "CVE exploitation of public-facing services."),
    "php_specific_attack": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.84, "PHP exploit pattern against exposed applications."),
    # Auth / credential behavior
    "brute_force_login": ("T1110", "Brute Force", "Credential Access", 0.85, "Repeated authentication failures indicate brute-force style access attempts."),
    "credential_stuffing": ("T1110.004", "Credential Stuffing", "Credential Access", 0.88, "Credential stuffing behavior detected."),
    "authentication_failures": ("T1110", "Brute Force", "Credential Access", 0.75, "Authentication failure clusters indicate credential attacks."),
    "low_slow_brute_force": ("T1110.003", "Password Spraying", "Credential Access", 0.82, "Cross-batch low-and-slow auth failures match password spraying patterns."),
    # Recon / scanner / campaign style behavior
    "known_scanner_ua": ("T1595", "Active Scanning", "Reconnaissance", 0.78, "Known scanner user-agent indicates reconnaissance scanning."),
    "rapid_404_generation": ("T1595", "Active Scanning", "Reconnaissance", 0.72, "Rapid 404 patterns indicate automated probing/scanning."),
    "technology_fingerprinting": ("T1595.002", "Vulnerability Scanning", "Reconnaissance", 0.7, "Technology fingerprinting aligns with vulnerability reconnaissance."),
    "api_schema_discovery": ("T1595", "Active Scanning", "Reconnaissance", 0.7, "API schema probing indicates reconnaissance activity."),
    "distributed_recon": ("T1595", "Active Scanning", "Reconnaissance", 0.8, "Distributed recon findings indicate scanning across many resources."),
    "scanner_persistence": ("T1595", "Active Scanning", "Reconnaissance", 0.8, "Persistent scanner signatures indicate ongoing reconnaissance."),
    "campaign_detection": ("T1595", "Active Scanning", "Reconnaissance", 0.74, "Shared signatures across multiple actors indicate coordinated recon campaign."),
    # DoS / impact behavior
    "http_flood": ("T1498", "Network Denial of Service", "Impact", 0.82, "HTTP flood traffic indicates network service disruption attempts."),
    "resource_exhaustion": ("T1498", "Network Denial of Service", "Impact", 0.78, "Resource exhaustion patterns align with DoS behavior."),
    "slowloris_indicator": ("T1498", "Network Denial of Service", "Impact", 0.78, "Slowloris-like traffic indicates service disruption attempts."),
    "rate_acceleration": ("T1498", "Network Denial of Service", "Impact", 0.7, "Sudden request-rate acceleration indicates potential flood behavior."),
    # Exfiltration
    "data_exfiltration_pattern": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", 0.72, "Cross-batch transfer patterns suggest data exfiltration activity."),
    # Composite / broad findings
    "kill_chain_progression": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.8, "Kill-chain progression includes exploit-stage behavior."),
    "multi_vector_attacker": ("T1595", "Active Scanning", "Reconnaissance", 0.68, "Multi-vector profile commonly begins with broad reconnaissance."),
    "off_hours_anomaly": ("T1078", "Valid Accounts", "Initial Access", 0.55, "Off-hours suspicious activity may involve unauthorized account use."),
    "privilege_escalation_probe": ("T1078", "Valid Accounts", "Initial Access", 0.55, "Privilege probing often follows account abuse patterns."),
}

_FAMILY_MITRE_MAP: Dict[str, MitreGuess] = {
    "injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.72, "Injection-family findings map to application exploitation."),
    "path_file": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.72, "Path/file abuse indicates exposed application exploitation."),
    "cve_exploit": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.85, "Known CVE exploit patterns against public-facing services."),
    "auth_access": ("T1110", "Brute Force", "Credential Access", 0.72, "Authentication and access abuse maps to credential access tactics."),
    "info_leakage": ("T1595.002", "Vulnerability Scanning", "Reconnaissance", 0.62, "Information leakage often follows reconnaissance probing."),
    "bot_scanner": ("T1595", "Active Scanning", "Reconnaissance", 0.68, "Scanner/bot signatures indicate recon activity."),
    "rate_dos": ("T1498", "Network Denial of Service", "Impact", 0.7, "Rate-abuse family maps to service disruption behavior."),
    "cache_redirect": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.6, "Cache/redirect abuse indicates application-layer attack paths."),
    "evasion": ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.6, "Evasion indicators often accompany exploitation attempts."),
}



class IncidentService:
    """
    Service for incident management.

    Groups related agent outputs into incidents and manages their lifecycle.
    Uses JSON file persistence to survive backend restarts.
    """

    _incidents: Dict[str, Incident] = {}
    _loaded: bool = False

    # Static content extensions to exclude
    _STATIC_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif',
        '.ico', '.svg', '.json', '.woff', '.woff2',
        '.ttf', '.eot', '.map', '.webp', '.avif',
        '.bmp', '.tiff', '.webm', '.mp4', '.mp3',
        '.pdf', '.zip', '.tar', '.gz'
    }

    # Legitimate bot patterns
    _LEGITIMATE_BOT_PATTERNS = [
        r'Googlebot/\d+\.\d+',
        r'Googlebot-Image/\d+\.\d+',
        r'Googlebot-Video/\d+\.\d+',
        r'Googlebot-News',
        r'bingbot/\d+\.\d+',
        r'YandexBot/\d+\.\d+',
        r'Baiduspider/\d+\.\d+',
        r'Baiduspider-render/\d+\.\d+',
    ]

    def __init__(self):
        self.incidents_created = 0
        # Load incidents from file on first init
        if not IncidentService._loaded:
            self._load_from_file()
            IncidentService._loaded = True

    @staticmethod
    def _is_static_content(url: Optional[str]) -> bool:
        """Check if URL is static content that should be excluded."""
        if not url:
            return False
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in IncidentService._STATIC_EXTENSIONS)

    @staticmethod
    def _is_legitimate_bot(user_agent: Optional[str]) -> bool:
        """Check if user agent is a legitimate search bot."""
        if not user_agent:
            return False
        import re
        for pattern in IncidentService._LEGITIMATE_BOT_PATTERNS:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def _should_exclude_threat(self, threat: DeterministicThreat) -> bool:
        """
        Check if a threat should be excluded from incident creation.
        
        Excludes threats that are:
        - Brute force/auth failures on static content only
        - From legitimate search bots
        """
        # Only filter brute force and authentication-related threats
        auth_related_rules = {
            'brute_force_login',
            'authentication_failures',
            'credential_stuffing'
        }
        
        if threat.rule_name not in auth_related_rules:
            return False
        
        # Check if all evidence is from static content
        if threat.sample_evidence:
            all_static = all(
                self._is_static_content(evidence) 
                for evidence in threat.sample_evidence
            )
            if all_static:
                logger.info(
                    f"Excluding threat {threat.rule_name} - all evidence is static content"
                )
                return True
        
        return False

    def _reload_if_needed(self) -> None:
        """Reload from file to pick up incidents created by other instances."""
        self._load_from_file()

    def _load_from_file(self) -> None:
        """Load incidents from JSON file."""
        incidents_file = _get_incidents_file()
        if incidents_file.exists():
            try:
                data = json.loads(incidents_file.read_text())
                for incident_data in data.get("incidents", []):
                    try:
                        incident = Incident.model_validate(incident_data)
                        IncidentService._incidents[str(incident.incident_id)] = incident
                    except Exception as e:
                        logger.warning(f"Failed to load incident: {e}")
                logger.info(
                    f"Loaded {len(IncidentService._incidents)} incidents from file | file={incidents_file}"
                )
            except Exception as e:
                logger.error(f"Failed to load incidents file: {e}")

    def _save_to_file(self) -> None:
        """Save all incidents to JSON file."""
        incidents_file = _get_incidents_file()
        try:
            data = {
                "incidents": [
                    incident.model_dump(mode='json', by_alias=True)
                    for incident in IncidentService._incidents.values()
                ],
                "saved_at": datetime.utcnow().isoformat(),
            }
            incidents_file.write_text(json.dumps(data, default=str, indent=2))
            logger.debug(f"Saved {len(IncidentService._incidents)} incidents to file")
        except Exception as e:
            logger.error(f"Failed to save incidents file: {e}")


    def create_from_agent_output(
        self,
        output: AgentOutput,
        chunk: BehavioralChunk,
    ) -> Incident:
        """
        Create an incident from an agent output.

        Args:
            output: AgentOutput from analysis
            chunk: Source behavioral chunk

        Returns:
            Created incident
        """
        # Generate title
        title = self._generate_title(output, chunk)

        # Determine priority
        priority = self._determine_priority(output)

        # Build description
        description = self._generate_description(output, chunk)

        # Extract MITRE references
        mitre_refs = []
        primary_tactic = None
        if output.mitre:
            mitre_refs.append(MitreReference(
                technique_id=output.mitre.technique_id,
                technique_name=output.mitre.technique_name,
                tactic=output.mitre.tactic,
                confidence=output.mitre.confidence,
                justification=output.mitre.justification,
            ))
            primary_tactic = output.mitre.tactic

        # Build initial timeline
        timeline = [
            IncidentTimeline(
                timestamp=chunk.time_window.start,
                event_type="detection",
                description="Behavioral anomaly detected",
            ),
            IncidentTimeline(
                timestamp=datetime.utcnow(),
                event_type="analysis",
                description="AI agent analysis completed",
            ),
        ]

        # Create incident
        triage = output.triage
        raw_log = triage.raw_log if triage and triage.raw_log else self._extract_raw_log_from_chunk(chunk)
        source_ip = triage.source_ip if triage and triage.source_ip else chunk.actor.src_ip
        source_username = triage.source_username if triage and triage.source_username else chunk.actor.username
        destination_ip = triage.destination_ip if triage and triage.destination_ip else self._extract_destination_ip_from_chunk(chunk)
        
        # Build correlation info showing IP and userid associations
        correlation_parts = []
        if source_ip:
            correlation_parts.append(f"IP: {source_ip}")
        if source_username:
            correlation_parts.append(f"User: {source_username}")
        correlation_info = " | ".join(correlation_parts) if correlation_parts else None
        
        attack_name = (
            triage.attack_name
            if triage and triage.attack_name
            else output.intent.suspected_intent
            if output.intent and output.intent.suspected_intent
            else (
                output.mitre.technique_name
                if output.mitre
                else title
            )
        )
        brief_description = (
            triage.brief_description
            if triage and triage.brief_description
            else triage.technical_summary
            if triage and triage.technical_summary
            else (
                output.behavioral.interpretation
                if output.behavioral and output.behavioral.interpretation
                else description
            )
        )
        recommended_action = (
            triage.recommended_action_short
            if triage and triage.recommended_action_short
            else triage.recommended_action
            if triage
            else "Investigate and validate findings."
        )

        incident = Incident(
            title=title,
            description=description,
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.AI_DETECTION,
            first_seen=chunk.time_window.start,
            last_seen=chunk.time_window.end,
            chunk_ids=[chunk.chunk_id],
            agent_output_ids=[output.analysis_id],
            file_ids=[chunk.file_id],
            primary_actor_ip=chunk.actor.src_ip,
            actor_ips=chunk.actor.src_ips or ([chunk.actor.src_ip] if chunk.actor.src_ip else []),
            primary_actor_username=chunk.actor.username,
            actor_usernames=[chunk.actor.username] if chunk.actor.username else [],
            affected_hosts=list(chunk.targets.dst_hosts)[:20],
            mitre_techniques=mitre_refs,
            primary_tactic=primary_tactic,
            overall_confidence=output.overall_confidence,
            executive_summary=output.triage.executive_summary if output.triage else "",
            technical_summary=output.triage.technical_summary if output.triage else "",
            recommended_actions=[output.triage.recommended_action] if output.triage else [],
            raw_log=raw_log,
            source_ip=source_ip,
            source_username=source_username,
            destination_ip=destination_ip,
            # Use behavioral agent's is_suspicious (triage no longer has suspicious field)
            suspicious=bool(output.behavioral.is_suspicious) if output.behavioral else priority != IncidentPriority.INFORMATIONAL,
            suspicious_indicator=(triage.suspicious_indicator if triage and triage.suspicious_indicator else self._derive_indicator_from_corpus(
                " ".join(
                    [
                        title,
                        description,
                        output.intent.suspected_intent if output.intent else "",
                        output.mitre.technique_name if output.mitre else "",
                        raw_log or "",
                    ]
                )
            )),
            attack_name=attack_name,
            brief_description=brief_description if brief_description else None,
            recommended_action=recommended_action,
            confidence_score=triage.confidence_score if triage else self._confidence_to_score(output.overall_confidence),
            mitre_tactic=(triage.mitre_tactic if triage and triage.mitre_tactic else (output.mitre.tactic if output.mitre else primary_tactic)),
            mitre_technique=(triage.mitre_technique if triage and triage.mitre_technique else (output.mitre.technique_id if output.mitre else None)),
            correlation_info=correlation_info,
            timeline=timeline,
            detection_tier="AI Analyzed" if output.overall_confidence >= 0.7 else "AI Analyzed - needs human review",
        )

        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1

        # Persist to file
        self._save_to_file()

        logger.info(
            f"Incident created | incident_id={incident.incident_id}, title={title}, priority={priority.value}"
        )

        return incident

    def create_from_deterministic_threat(
        self,
        threat: DeterministicThreat,
        file_id=None,
    ) -> Optional[Incident]:
        """Create an incident from a Tier 1 deterministic threat finding."""
        from datetime import datetime

        # The user requested that all threats be created as incidents, even if they are FPs
        # (We bypass _should_exclude_threat)
        severity_to_priority = {
            "critical": IncidentPriority.CRITICAL,
            "high": IncidentPriority.HIGH,
            "medium": IncidentPriority.MEDIUM,
            "low": IncidentPriority.LOW,
            "info": IncidentPriority.INFORMATIONAL,
        }
        priority = severity_to_priority.get(
            threat.severity.value, IncidentPriority.MEDIUM
        )

        evidence_str = "; ".join(threat.sample_evidence[:3])
        actor = threat.src_ip or "Unknown"
        
        # Build correlation info showing IP and userid associations
        correlation_parts = []
        if threat.src_ip:
            correlation_parts.append(f"IP: {threat.src_ip}")
            
        primary_username = threat.usernames[0] if getattr(threat, "usernames", None) else threat.src_username
        all_usernames = getattr(threat, "usernames", None) or threat.src_usernames

        if primary_username:
            correlation_parts.append(f"User: {primary_username}")
        if len(threat.src_ips) > 1:
            correlation_parts.append(f"Additional IPs: {', '.join(threat.src_ips[1:3])}")
        if len(all_usernames) > 1:
            correlation_parts.append(f"Additional Users: {', '.join(all_usernames[1:3])}")
        correlation_info = " | ".join(correlation_parts) if correlation_parts else None

        incident = Incident(
            title=f"[{threat.category.upper()}] {threat.description[:60]} from {actor}",
            description=(
                f"Deterministic detection: {threat.description}\n"
                f"Rule: {threat.rule_name}\n"
                f"Matches: {threat.match_count}\n"
                f"Evidence: {evidence_str[:300]}"
            ),
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.DETERMINISTIC,
            first_seen=threat.first_seen or datetime.utcnow(),
            last_seen=threat.last_seen or datetime.utcnow(),
            file_ids=[file_id] if file_id else [],
            primary_actor_ip=threat.src_ip,
            actor_ips=threat.src_ips,
            primary_actor_username=primary_username,
            actor_usernames=all_usernames,
            overall_confidence=threat.confidence,
            detection_tier="deterministic",
            detection_rule=threat.rule_name,
            executive_summary=f"{threat.description} ({threat.match_count} detections)",
            recommended_actions=[f"Investigate {threat.category} from {actor}"],
            raw_log=threat.sample_evidence[0][:300] if threat.sample_evidence else None,
            source_ip=threat.src_ip,
            source_username=primary_username,
            destination_ip=self._extract_destination_ip_from_text(evidence_str),
            suspicious=priority != IncidentPriority.INFORMATIONAL,
            suspicious_indicator=self._derive_indicator_from_corpus(" ".join([threat.category, threat.rule_name, evidence_str])),
            attack_name=threat.rule_name,
            brief_description=threat.description,
            recommended_action=f"Investigate {threat.category} from {actor}",
            confidence_score=self._confidence_to_score(threat.confidence),
            correlation_info=correlation_info,
            mitre_tactic=None,
            mitre_technique=None,
            timeline=[
                IncidentTimeline(
                    timestamp=threat.first_seen or datetime.utcnow(),
                    event_type="detection",
                    description=f"Deterministic rule matched: {threat.rule_name}",
                ),
            ],
        )
        self._apply_mitre_fallback(incident, family_hint=threat.family.value)

        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        self._save_to_file()

        logger.info(
            f"Deterministic incident created | incident_id={incident.incident_id}, rule={threat.rule_name}, priority={priority.value}"
        )
        return incident

    def create_from_correlation(
        self,
        finding,
        file_id=None,
    ) -> Incident:
        """Create an incident from a Tier 2 day-level correlation finding."""
        from datetime import datetime

        sev_map = {
            "critical": IncidentPriority.CRITICAL,
            "high": IncidentPriority.HIGH,
            "medium": IncidentPriority.MEDIUM,
        }
        priority = sev_map.get(finding.severity, IncidentPriority.MEDIUM)
        
        # Build correlation info
        correlation_parts = []
        if finding.src_ip:
            correlation_parts.append(f"IP: {finding.src_ip}")
        src_username = getattr(finding, "src_username", None)
        if src_username:
            correlation_parts.append(f"User: {src_username}")
        correlation_info = " | ".join(correlation_parts) if correlation_parts else None

        incident = Incident(
            title=f"[CORRELATION] {finding.description[:80]}",
            description=(
                f"Day-level correlation: {finding.description}\n"
                f"Rule: {finding.correlation_rule}\n"
                f"Evidence: {str(finding.evidence)[:300]}"
            ),
            status=IncidentStatus.NEW,
            priority=priority,
            source=IncidentSource.CORRELATION,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            file_ids=[file_id] if file_id else [],
            primary_actor_ip=finding.src_ip,
            actor_ips=[finding.src_ip] if finding.src_ip else [],
            primary_actor_username=src_username,
            actor_usernames=[src_username] if src_username else [],
            overall_confidence=finding.confidence,
            detection_tier="Correlation",
            detection_rule=finding.correlation_rule,
            executive_summary=finding.description,
            recommended_actions=[f"Investigate correlated activity from {finding.src_ip}"],
            raw_log=str(getattr(finding, "evidence", ""))[:300],
            source_ip=finding.src_ip,
            source_username=src_username,
            destination_ip=self._extract_destination_ip_from_text(str(getattr(finding, "evidence", ""))),
            suspicious=priority != IncidentPriority.INFORMATIONAL,
            suspicious_indicator=self._derive_indicator_from_corpus(
                " ".join([finding.description or "", finding.correlation_rule or "", str(getattr(finding, "evidence", ""))])
            ),
            attack_name=finding.correlation_rule,
            brief_description=finding.description if finding.description else None,
            recommended_action=f"Investigate correlated activity from {finding.src_ip}",
            confidence_score=self._confidence_to_score(finding.confidence),
            correlation_info=correlation_info,
            mitre_tactic=None,
            mitre_technique=None,
            timeline=[
                IncidentTimeline(
                    timestamp=datetime.utcnow(),
                    event_type="correlation",
                    description=f"Day-level correlation: {finding.correlation_rule}",
                ),
            ],
        )
        self._apply_mitre_fallback(incident)

        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1
        self._save_to_file()

        logger.info(
            f"Correlation incident created | incident_id={incident.incident_id}, rule={finding.correlation_rule}"
        )
        return incident

    def create_from_multiple_outputs(
        self,
        outputs: List[Tuple[AgentOutput, BehavioralChunk]],
    ) -> Incident:
        """
        Create a single incident from multiple related outputs.

        Args:
            outputs: List of (AgentOutput, BehavioralChunk) tuples

        Returns:
            Created incident
        """
        if not outputs:
            raise ValueError("No outputs provided")

        # Sort by time
        sorted_outputs = sorted(
            outputs,
            key=lambda x: x[1].time_window.start,
        )

        first_output, first_chunk = sorted_outputs[0]
        last_output, last_chunk = sorted_outputs[-1]

        # Generate combined title
        title = f"Multi-event incident: {len(outputs)} related activities"

        # Use highest priority
        highest_priority = IncidentPriority.INFORMATIONAL
        for output, _ in outputs:
            priority = self._determine_priority(output)
            if self._priority_value(priority) > self._priority_value(highest_priority):
                highest_priority = priority

        # Collect all data
        chunk_ids = []
        output_ids = []
        file_ids = set()
        actor_ips = set()
        affected_hosts = set()
        mitre_refs = []
        tactics = set()

        for output, chunk in outputs:
            chunk_ids.append(chunk.chunk_id)
            output_ids.append(output.analysis_id)
            file_ids.add(chunk.file_id)

            if chunk.actor.src_ip:
                actor_ips.add(chunk.actor.src_ip)
            actor_ips.update(chunk.actor.src_ips or [])
            affected_hosts.update(chunk.targets.dst_hosts)

            if output.mitre:
                mitre_refs.append(MitreReference(
                    technique_id=output.mitre.technique_id,
                    technique_name=output.mitre.technique_name,
                    tactic=output.mitre.tactic,
                    confidence=output.mitre.confidence,
                    justification=output.mitre.justification,
                ))
                tactics.add(output.mitre.tactic)

        # Build timeline
        timeline = []
        for output, chunk in sorted_outputs:
            timeline.append(IncidentTimeline(
                timestamp=chunk.time_window.start,
                event_type="detection",
                description=output.behavioral.interpretation if output.behavioral else "Activity detected",
                actor=chunk.actor.src_ip,
            ))

        # Average confidence
        avg_confidence = sum(
            o.overall_confidence for o, _ in outputs
        ) / len(outputs)

        incident = Incident(
            title=title,
            description=f"Correlated incident spanning {len(outputs)} behavioral chunks",
            status=IncidentStatus.NEW,
            priority=highest_priority,
            source=IncidentSource.CORRELATION,
            first_seen=first_chunk.time_window.start,
            last_seen=last_chunk.time_window.end,
            chunk_ids=chunk_ids,
            agent_output_ids=output_ids,
            file_ids=list(file_ids),
            primary_actor_ip=list(actor_ips)[0] if actor_ips else None,
            actor_ips=sorted(actor_ips),
            affected_hosts=sorted(affected_hosts)[:50],
            mitre_techniques=mitre_refs,
            primary_tactic=list(tactics)[0] if len(tactics) == 1 else None,
            overall_confidence=avg_confidence,
            raw_log=self._extract_raw_log_from_chunk(first_chunk),
            source_ip=first_chunk.actor.src_ip,
            destination_ip=self._extract_destination_ip_from_chunk(first_chunk),
            suspicious=highest_priority != IncidentPriority.INFORMATIONAL,
            suspicious_indicator=self._derive_indicator_from_corpus(" ".join([title, first_output.behavioral.interpretation if first_output.behavioral else ""])),
            attack_name=first_output.intent.suspected_intent if first_output.intent else title,
            brief_description=first_output.behavioral.interpretation if first_output.behavioral else title,
            recommended_action=first_output.triage.recommended_action if first_output.triage else "Investigate correlated sequence.",
            confidence_score=self._confidence_to_score(avg_confidence),
            mitre_tactic=first_output.mitre.tactic if first_output.mitre else (list(tactics)[0] if len(tactics) == 1 else None),
            mitre_technique=first_output.mitre.technique_id if first_output.mitre else None,
            timeline=timeline,
            detection_tier="Correlation",
        )

        self._incidents[str(incident.incident_id)] = incident
        self.incidents_created += 1

        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get an incident by ID."""
        self._reload_if_needed()
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        if self._apply_mitre_fallback(incident):
            self._save_to_file()
        return incident

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        priority: Optional[IncidentPriority] = None,
        limit: int = 100,
    ) -> List[IncidentSummary]:
        """
        List incidents with optional filters.

        Args:
            status: Filter by status
            priority: Filter by priority
            limit: Maximum number to return

        Returns:
            List of incident summaries
        """
        # Reload from file to pick up new incidents (fixes visibility bug)
        self._reload_if_needed()
        incidents = list(self._incidents.values())
        updated = False
        for incident in incidents:
            if self._apply_mitre_fallback(incident):
                updated = True
        if updated:
            self._save_to_file()

        # Apply filters
        if status:
            incidents = [i for i in incidents if i.status == status]
        if priority:
            incidents = [i for i in incidents if i.priority == priority]

        # Sort by priority then time (normalize tz-aware/naive datetimes)
        def _to_naive_utc(dt: datetime) -> datetime:
            """Convert any datetime to naive UTC for safe comparison."""
            if dt is None:
                return datetime(2000, 1, 1)
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt

        incidents.sort(
            key=lambda i: (-self._priority_value(i.priority), _to_naive_utc(i.first_seen)),
            reverse=True,
        )

        # Convert to summaries
        summaries = []
        for incident in incidents[:limit]:
            raw_log = incident.raw_log or self._extract_raw_log(incident)
            suspicious_indicator = incident.suspicious_indicator or self._derive_suspicious_indicator(incident)
            confidence_score = incident.confidence_score or self._confidence_to_score(incident.overall_confidence)
            mitre_technique = incident.mitre_technique or (
                incident.mitre_techniques[0].technique_id
                if incident.mitre_techniques
                else None
            )
            summaries.append(IncidentSummary(
                incident_id=incident.incident_id,
                title=incident.title,
                status=incident.status,
                priority=incident.priority,
                first_seen=incident.first_seen,
                last_seen=incident.last_seen,
                chunk_count=len(incident.chunk_ids),
                confidence=incident.overall_confidence,
                primary_tactic=incident.primary_tactic,
                file_ids=incident.file_ids,
                raw_log=raw_log,
                source_ip=incident.source_ip or incident.primary_actor_ip,
                destination_ip=incident.destination_ip or (incident.affected_hosts[0] if incident.affected_hosts else None),
                suspicious=incident.suspicious if incident.suspicious is not None else incident.priority != IncidentPriority.INFORMATIONAL,
                suspicious_indicator=suspicious_indicator,
                attack_name=incident.attack_name or incident.detection_rule or incident.title,
                brief_description=incident.brief_description or incident.executive_summary or incident.description[:220],
                recommended_action=incident.recommended_action or (incident.recommended_actions[0] if incident.recommended_actions else "Investigate context and validate indicators."),
                confidence_score=confidence_score,
                mitre_tactic=incident.mitre_tactic or incident.primary_tactic,
                mitre_technique=mitre_technique,
            ))

        return summaries

    def _infer_mitre_guess(
        self,
        rule_name: Optional[str],
        category: Optional[str] = None,
        family: Optional[str] = None,
    ) -> MitreGuess | None:
        """Infer MITRE mapping from deterministic/correlation metadata."""
        rule_key = (rule_name or "").strip().lower()
        category_key = (category or "").strip().lower()
        family_key = (family or "").strip().lower()

        if rule_key and rule_key in _RULE_MITRE_MAP:
            return _RULE_MITRE_MAP[rule_key]
        if family_key and family_key in _FAMILY_MITRE_MAP:
            return _FAMILY_MITRE_MAP[family_key]

        combined = f"{rule_key} {category_key}"
        if any(token in combined for token in ("brute", "credential", "auth_fail", "password_spray")):
            return ("T1110", "Brute Force", "Credential Access", 0.7, "Keyword-based mapping for credential attack behavior.")
        if any(token in combined for token in ("recon", "scanner", "fingerprint", "discovery", "campaign")):
            return ("T1595", "Active Scanning", "Reconnaissance", 0.65, "Keyword-based mapping for reconnaissance activity.")
        if any(token in combined for token in ("dos", "flood", "resource_exhaustion", "rate_limit")):
            return ("T1498", "Network Denial of Service", "Impact", 0.65, "Keyword-based mapping for service disruption behavior.")
        if any(token in combined for token in ("exfil", "leak", "data_theft")):
            return ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", 0.65, "Keyword-based mapping for exfiltration indicators.")
        if any(token in combined for token in ("injection", "traversal", "inclusion", "rce", "exploit")):
            return ("T1190", "Exploit Public-Facing Application", "Initial Access", 0.68, "Keyword-based mapping for exploit behavior.")

        return None

    def _infer_incident_family_hint(self, incident: Incident) -> str | None:
        """Derive a best-effort family hint from persisted incident fields."""
        if incident.source == IncidentSource.DETERMINISTIC:
            corpus = " ".join(
                [
                    incident.detection_rule or "",
                    incident.title or "",
                    incident.description or "",
                ]
            ).lower()
            for family in _FAMILY_MITRE_MAP:
                if family in corpus:
                    return family
        return None

    def _apply_mitre_fallback(self, incident: Incident, family_hint: Optional[str] = None) -> bool:
        """
        Ensure incident has MITRE tactic/technique populated.

        Returns True when incident was mutated.
        """
        has_tactic = bool(incident.mitre_tactic or incident.primary_tactic)
        has_technique = bool(
            incident.mitre_technique
            or (incident.mitre_techniques and incident.mitre_techniques[0].technique_id)
        )
        if has_tactic and has_technique:
            return False

        title_hint = ""
        if incident.title and incident.title.startswith("[") and "]" in incident.title:
            title_hint = incident.title.split("]", 1)[0].strip("[]")

        inferred_family = family_hint or self._infer_incident_family_hint(incident)
        guess = self._infer_mitre_guess(
            incident.detection_rule,
            category=title_hint or incident.description,
            family=inferred_family,
        )
        if not guess:
            return False

        technique_id, technique_name, tactic, confidence, justification = guess
        changed = False

        if not incident.primary_tactic:
            incident.primary_tactic = tactic
            changed = True
        if not incident.mitre_tactic:
            incident.mitre_tactic = tactic
            changed = True
        if not incident.mitre_technique:
            incident.mitre_technique = technique_id
            changed = True
        if not incident.mitre_techniques:
            incident.mitre_techniques = [
                MitreReference(
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    confidence=max(0.0, min(1.0, confidence)),
                    justification=justification,
                )
            ]
            changed = True

        return changed

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        notes: Optional[str] = None,
    ) -> Incident | None:
        """Update incident status."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        incident.status = status
        incident.updated_at = datetime.utcnow()

        if status == IncidentStatus.RESOLVED:
            incident.resolved_at = datetime.utcnow()

        if notes:
            incident.notes.append(f"[{datetime.utcnow().isoformat()}] {notes}")

        # Add to timeline
        incident.timeline.append(IncidentTimeline(
            timestamp=datetime.utcnow(),
            event_type="status_change",
            description=f"Status changed to {status.value}",
        ))

        # Persist changes
        self._save_to_file()

        return incident

    def generate_report(self, incident_id: str) -> IncidentReport | None:
        """Generate a full incident report."""
        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        return IncidentReport(
            incident=incident,
        )

    def list_incidents_for_file(self, file_id: str) -> List[Incident]:
        """Return incidents linked to a specific file_id."""
        self._reload_if_needed()
        matches: List[Incident] = []
        for incident in self._incidents.values():
            file_ids = [str(fid) for fid in (incident.file_ids or [])]
            if file_id in file_ids:
                matches.append(incident)
        return matches

    def _generate_title(self, output: AgentOutput, chunk: BehavioralChunk) -> str:
        """Generate incident title."""
        if output.behavioral and output.behavioral.is_suspicious:
            base = output.behavioral.interpretation[:50]
        else:
            base = "Behavioral anomaly detected"

        actor = chunk.actor.src_ip or "Unknown actor"
        return f"{base} from {actor}"

    def _generate_description(
        self,
        output: AgentOutput,
        chunk: BehavioralChunk,
    ) -> str:
        """Generate incident description."""
        parts = []

        if output.behavioral:
            parts.append(f"Behavior: {output.behavioral.interpretation}")

        if output.intent:
            parts.append(f"Suspected intent: {output.intent.suspected_intent}")

        if output.mitre:
            parts.append(
                f"MITRE mapping: {output.mitre.technique_name} ({output.mitre.technique_id})"
            )

        if output.triage:
            parts.append(f"Risk: {output.triage.risk_reason}")

        return "\n".join(parts)

    def _determine_priority(self, output: AgentOutput) -> IncidentPriority:
        """Determine incident priority from agent output."""
        if output.triage:
            # Map agent priority to incident priority
            from shared_models.agents import IncidentPriority as AgentPriority
            priority_map = {
                AgentPriority.CRITICAL: IncidentPriority.CRITICAL,
                AgentPriority.HIGH: IncidentPriority.HIGH,
                AgentPriority.MEDIUM: IncidentPriority.MEDIUM,
                AgentPriority.LOW: IncidentPriority.LOW,
                AgentPriority.INFORMATIONAL: IncidentPriority.INFORMATIONAL,
            }
            return priority_map.get(output.triage.priority, IncidentPriority.MEDIUM)

        # Fallback based on confidence
        if output.overall_confidence >= 0.8:
            return IncidentPriority.HIGH
        elif output.overall_confidence >= 0.6:
            return IncidentPriority.MEDIUM
        else:
            return IncidentPriority.LOW

    def _priority_value(self, priority: IncidentPriority) -> int:
        """Get numeric value for priority sorting."""
        values = {
            IncidentPriority.CRITICAL: 5,
            IncidentPriority.HIGH: 4,
            IncidentPriority.MEDIUM: 3,
            IncidentPriority.LOW: 2,
            IncidentPriority.INFORMATIONAL: 1,
        }
        return values.get(priority, 0)

    def _confidence_to_score(self, confidence: float) -> int:
        """Convert 0-1 confidence to 1-10 score."""
        return max(1, min(10, int(round((confidence or 0.0) * 10))))

    def _extract_raw_log_from_chunk(self, chunk: BehavioralChunk) -> str | None:
        """Extract a raw-log sample from chunk events."""
        events = getattr(chunk, "events", []) or []
        if not events:
            return None
        event = events[0]
        if isinstance(event, dict):
            for key in ("raw_log", "logevent", "message", "raw_message", "request", "uri"):
                value = event.get(key)
                if value:
                    return str(value)[:300]
            raw_data = event.get("raw_data")
            if isinstance(raw_data, dict):
                for key in ("logevent", "message", "request", "uri"):
                    value = raw_data.get(key)
                    if value:
                        return str(value)[:300]
            if raw_data:
                return str(raw_data)[:300]
        return str(event)[:300]

    def _extract_destination_ip_from_chunk(self, chunk: BehavioralChunk) -> str | None:
        """Extract destination ip or host from chunk."""
        targets = getattr(chunk, "targets", None)
        if targets:
            dst_ips = getattr(targets, "dst_ips", None) or []
            if dst_ips:
                return str(dst_ips[0])
            dst_hosts = getattr(targets, "dst_hosts", None) or []
            if dst_hosts:
                return str(dst_hosts[0])
        return None

    def _extract_destination_ip_from_text(self, value: str) -> str | None:
        """Best-effort destination IP extraction from free text."""
        import re

        if not value:
            return None
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
        if len(ip_matches) >= 2:
            return ip_matches[1]
        return None

    def _derive_indicator_from_corpus(self, corpus: str) -> str:
        """Derive suspicious indicator keyword from a text corpus."""
        text = (corpus or "").lower()
        if "url" in text or "uri" in text or "path" in text:
            return "url"
        if "referer" in text or "referrer" in text:
            return "referer"
        if "user agent" in text or "user_agent" in text:
            return "user_agent"
        if "payload" in text or "injection" in text or "command" in text:
            return "payload"
        if "ip" in text or "scanner" in text or "recon" in text:
            return "source ip"
        return "null"

    def _extract_raw_log(self, incident: Incident) -> str | None:
        """Extract a compact raw-log sample for incident list view."""
        description = incident.description or ""
        marker = "Evidence:"
        if marker in description:
            sample = description.split(marker, 1)[1].strip()
            return sample[:220] if sample else None
        if incident.timeline:
            return incident.timeline[0].description[:220]
        return description[:220] if description else None

    def _derive_suspicious_indicator(self, incident: Incident) -> str | None:
        """Derive suspicious indicator keyword for UI display."""
        corpus = " ".join(
            [
                incident.title or "",
                incident.description or "",
                incident.detection_rule or "",
                incident.primary_tactic or "",
            ]
        )
        return self._derive_indicator_from_corpus(corpus)

    def get_stats(self) -> Dict[str, Any]:
        """Get incident statistics."""
        status_counts = defaultdict(int)
        priority_counts = defaultdict(int)

        for incident in self._incidents.values():
            status_counts[incident.status.value] += 1
            priority_counts[incident.priority.value] += 1

        return {
            "total_incidents": len(self._incidents),
            "incidents_created": self.incidents_created,
            "by_status": dict(status_counts),
            "by_priority": dict(priority_counts),
        }
