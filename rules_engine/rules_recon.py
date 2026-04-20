"""Families 3 & 4: Information Leakage & Recon (11) + Path & File Access (5)"""

from __future__ import annotations

from typing import Optional

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent
import re
from urllib.parse import unquote, urlparse
from collections import defaultdict
from core.logging import get_logger
from core.config import get_settings

logger = get_logger(__name__)

# --- Re-defined Regexes for Enhanced Detection ---

# Sensitive config/env/credential files
SENSITIVE_FILE_REGEX = re.compile(
    r"(?i)^/(\.env(\.[a-z0-9_-]+)?|wp-config\.php|config\.(yml|yaml|json)"
    r"|application\.(properties|yml)|\.htpasswd|\.htaccess|web\.config)$"
)

# Backup and archive files
BACKUP_FILE_REGEX = re.compile(
    r"(?i).*\.(bak|old|orig|copy|save|swp|tmp|temp|sql|dump|tar|gz|zip|rar|7z)(?:\?|$)|.*~$"
)

# Source code repositories and IDE metadata
SOURCE_CODE_REGEX = re.compile(
    r"(?i)/(\.git/(HEAD|config|index|objects|refs)|\.svn/(entries|wc\.db)|\.hg/|\.DS_Store|\.idea/)"
)

# Debug and admin info disclosure endpoints
DEBUG_ENDPOINT_REGEX = re.compile(
    r"(?i)/((debug|_debug|trace|_trace)\b|actuator(/|$)|console(/|$)|phpinfo(\.php)?|server-(status|info)|_profiler)"
)

def _check_recon_probing(
    events: list[NormalizedEvent],
    regex: re.Pattern,
    rule_name: str,
    category: str,
    family: ThreatFamily,
    probing_rule_name: str
) -> list[ThreatMatch]:
    """Helper to detect systematic probing for sensitive files/paths."""
    settings = get_settings()
    uri_threshold = settings.probe_uri_threshold
    count_threshold = settings.probe_count_threshold

    # Group by IP: track distinct URIs and total events
    ip_stats = defaultdict(lambda: {"uris": set(), "events": []})

    for ev in events:
        if ev.http_status not in (403, 404):
            continue
        uri = (ev.uri_path or "").lower()
        if regex.search(uri):
            ip = ev.src_ip or "-"
            ip_stats[ip]["uris"].add(uri)
            ip_stats[ip]["events"].append(ev)

    matches = []
    for ip, stats in ip_stats.items():
        if len(stats["uris"]) >= uri_threshold and len(stats["events"]) >= count_threshold:
            last_ev = stats["events"][-1]
            matches.append(ThreatMatch(
                event_id=last_ev.event_id,
                rule_name=probing_rule_name,
                category=category,
                family=family,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                evidence=(
                    f"Systematic probing detected from {ip}: "
                    f"{len(stats['uris'])} distinct sensitive URIs, "
                    f"{len(stats['events'])} total hits (thresholds: {uri_threshold}/{count_threshold})"
                ),
                matched_field="uri_path",
                uri=last_ev.uri_path,
                timestamp=last_ev.timestamp,
                src_ip=last_ev.src_ip,
            ))
    return matches

SENSITIVE_PATHS = [
    r"^/export(/|$)",
    r"^/download(/|$)",
    r"^/dump(/|$)",
    r"^/api/users(/|$)",
    r"^/api/data(/|$)"
]

SINGLE_THRESHOLD = 500000       # 500 KB
AGGREGATE_THRESHOLD = 2000000  # 2 MB


def normalize_uri(uri: str) -> str:
    try:
        if not uri:
            return ""
        uri = unquote(uri).lower()
        return urlparse(uri).path
    except Exception as e:
        logger.warning(f"normalize_uri failed for uri '{uri}': {e}", exc_info=True)
        return ""


def is_sensitive_path(uri: str) -> bool:
    try:
        path = normalize_uri(uri)
        return any(re.search(p, path) for p in SENSITIVE_PATHS)
    except Exception as e:
        logger.warning(f"is_sensitive_path failed for uri '{uri}': {e}", exc_info=True)
        return False


class SensitiveFileExposureRule(ThreatRule):
    name = "sensitive_file_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Exposure or probing of sensitive config/credential files (.env, wp-config, etc.)"
    check_fields = ["uri_path"]
    
    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.uri_path or "").lower()
        if event.http_status == 200 and SENSITIVE_FILE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="sensitive_file_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                evidence=f"Sensitive file exposed: {uri}",
                matched_field="uri_path",
                uri=event.uri_path,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """Detect batch-level probing (403/404)."""
        return _check_recon_probing(
            events, SENSITIVE_FILE_REGEX,
            "sensitive_file_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "sensitive_file_probing"
        )


class BackupFileHuntingRule(ThreatRule):
    name = "backup_file_hunting"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Exposure or probing for backup/archive files (.bak, .zip, .sql, etc.)"
    check_fields = ["uri_path"]

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.uri_path or "").lower()
        if event.http_status == 200 and BACKUP_FILE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="backup_file_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                evidence=f"Backup/archive file exposed: {uri}",
                matched_field="uri_path",
                uri=event.uri_path,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """Detect batch-level probing (403/404)."""
        return _check_recon_probing(
            events, BACKUP_FILE_REGEX,
            "backup_file_hunting", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "backup_file_probing"
        )


class SourceCodeExposureRule(ThreatRule):
    name = "source_code_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Exposure or probing for source code repository files (.git, .svn, etc.)"
    check_fields = ["uri_path"]

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.uri_path or "").lower()
        if event.http_status == 200 and SOURCE_CODE_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="source_code_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.9,
                evidence=f"Source code metadata/repo file exposed: {uri}",
                matched_field="uri_path",
                uri=event.uri_path,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """Detect batch-level probing (403/404)."""
        return _check_recon_probing(
            events, SOURCE_CODE_REGEX,
            "source_code_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "source_code_probing"
        )


class DebugEndpointExposureRule(ThreatRule):
    name = "debug_endpoint_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Exposure or probing for debug/admin/instrumentation endpoints"
    check_fields = ["uri_path"]

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        """Detect immediate SUCCESSFUL exposure (200 OK)."""
        uri = (event.uri_path or "").lower()
        if event.http_status == 200 and DEBUG_ENDPOINT_REGEX.search(uri):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name="debug_endpoint_exposed",
                category=self.category,
                family=self.family,
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                evidence=f"Debug/admin endpoint exposed: {uri}",
                matched_field="uri_path",
                uri=event.uri_path,
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None

    @staticmethod
    def check_batch(events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """Detect batch-level probing (403/404)."""
        return _check_recon_probing(
            events, DEBUG_ENDPOINT_REGEX,
            "debug_endpoint_exposure", "sensitive_information_disclosure",
            ThreatFamily.INFO_LEAKAGE, "debug_endpoint_probing"
        )


class ErrorDetailDisclosureRule(ThreatRule):
    name = "error_detail_disclosure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Large 5xx response possibly containing error details"
    check_fields = []

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        try:
            if event.http_status and event.http_status >= 500:
                resp_size = event.response_size or event.bytes_sent or 0
                if resp_size > 5000:
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"HTTP {event.http_status} with {resp_size}B response",
                        matched_field="http_status",
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
            return None
        except Exception as e:
            logger.error(f"[{self.name}] match failed for event {event.event_id}: {e}", exc_info=True)
            return None


class TechFingerprintingRule(ThreatRule):
    name = "technology_fingerprinting"
    category = "recon_scanner"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.65
    description = "Technology stack fingerprinting probes"
    check_fields = ["uri_path"]
    patterns = [
        r"/wp-(?:admin|login|includes|content|cron)",
        r"/joomla|/administrator",
        r"/drupal|/sites/default",
        r"/phpmyadmin|/pma|/adminer",
        r"/solr(?:/|$)",
        r"/jenkins(?:/|$)",
        r"/grafana(?:/|$)",
        r"/kibana(?:/|$)",
    ]


class APISchemaDiscoveryRule(ThreatRule):
    name = "api_schema_discovery"
    category = "recon_scanner"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "API documentation/schema discovery"
    check_fields = ["uri_path"]
    patterns = [
        r"/swagger(?:-ui|-resources)?(?:/|$|\.)",
        r"/api-docs(?:/|$)",
        r"/openapi\.(?:json|yaml)",
        r"/graphql/schema",
        r"/\.well-known/",
    ]


class HardcodedCredsInURLRule(ThreatRule):
    name = "hardcoded_creds_url"
    category = "hardcoded_credential_exposure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Credentials/secrets in URL query string"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"[?&](?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|private_key)\s*=\s*[^&\s]{3,}",
    ]


class HardcodedSecretPatternRule(ThreatRule):
    name = "hardcoded_secret_pattern"
    category = "hardcoded_credential_exposure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.88
    description = "Known credential/token patterns observed in request data"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"ghp_[A-Za-z0-9]{36}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"xox[baprs]-[A-Za-z0-9-]{10,48}",
        r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA)\s+PRIVATE\s+KEY-----",
    ]


class DataExfiltrationBasicRule(ThreatRule):
    name = "data_exfil_single"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Large POST to sensitive endpoint (single-event exfiltration)"
    check_fields = []

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        try:
            uri = (event.uri_path or "").lower()
            method = (event.http_method or "").upper()
            bytes_out = event.bytes_sent or 0

            if method == "POST" and is_sensitive_path(uri) and bytes_out > SINGLE_THRESHOLD:
                return ThreatMatch(
                    event_id=event.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"POST to sensitive path {uri[:80]} with {bytes_out}B sent (threshold: {SINGLE_THRESHOLD}B)",
                    matched_field="uri_path",
                    uri=event.uri_path,
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                )
            return None
        except Exception as e:
            logger.error(f"[{self.name}] match failed for event {event.event_id}: {e}", exc_info=True)
            return None


class DataExfiltrationLowSlowRule(ThreatRule):
    name = "data_exfil_low_slow"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.65
    description = "Low-and-slow data exfiltration: aggregate bytes to sensitive endpoints"
    check_fields = []

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        # Handled at batch level via check_batch; per-event match is a no-op
        return None

    @staticmethod
    def check_batch(events: list[NormalizedEvent]) -> list[ThreatMatch]:
        """Check aggregate bytes_sent per src_ip across all sensitive-path events."""
        try:
            traffic: dict[str, int] = defaultdict(int)
            last_event_by_ip: dict[str, NormalizedEvent] = {}

            for ev in events:
                try:
                    uri = (ev.uri_path or "").lower()
                    if not is_sensitive_path(uri):
                        continue
                    ip = ev.src_ip or "-"
                    traffic[ip] += ev.bytes_sent or 0
                    last_event_by_ip[ip] = ev
                except Exception as e:
                    logger.warning(f"[data_exfil_low_slow] Failed to process event {ev.event_id}: {e}", exc_info=True)

            matches = []
            for ip, total_bytes in traffic.items():
                try:
                    if total_bytes > AGGREGATE_THRESHOLD:
                        last = last_event_by_ip[ip]
                        matches.append(ThreatMatch(
                            event_id=last.event_id,
                            rule_name="data_exfil_low_slow",
                            category="sensitive_information_disclosure",
                            family=ThreatFamily.INFO_LEAKAGE,
                            severity=ThreatSeverity.HIGH,
                            confidence=0.65,
                            evidence=f"Low-and-slow exfil from {ip}: {total_bytes}B sent to sensitive paths (threshold: {AGGREGATE_THRESHOLD}B)",
                            matched_field="bytes_sent",
                            uri=last.uri_path,
                            timestamp=last.timestamp,
                            src_ip=last.src_ip,
                        ))
                except Exception as e:
                    logger.warning(f"[data_exfil_low_slow] Failed to build ThreatMatch for IP {ip}: {e}", exc_info=True)
            return matches
        except Exception as e:
            logger.error(f"[data_exfil_low_slow] check_batch failed: {e}", exc_info=True)
            return []


# Family 4: Path & File

class PathTraversalRule(ThreatRule):
    name = "path_traversal"
    category = "path_traversal"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.HIGH
    confidence = 0.9
    description = "Path traversal attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"\.\./",
        r"\.\.\\ ",
        r"\.\.%2[fF]",
        r"\.\.%255[cC]",
        r"%2[eE]%2[eE]%2[fF]",
        r"\.\.%c0%af",
    ]


class LFIRule(ThreatRule):
    name = "local_file_inclusion"
    category = "local_file_inclusion"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Local file inclusion attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self/(?:environ|cmdline|fd|maps)",
        r"/windows/system32",
        r"/boot\.ini",
        r"(?:file|page|include|path|doc|template)\s*=\s*(?:\.\./|/(?:etc/passwd|etc/shadow|proc/self/environ|proc/version|win\.ini|boot\.ini|web\.config|wp-config\.php|application\.yml|\.env))",
    ]


class RFIRule(ThreatRule):
    name = "remote_file_inclusion"
    category = "rfi"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Remote file inclusion attempt"
    check_fields = ["uri_path", "uri_query"]
    patterns = [
        r"(?:file|page|include|path|url)\s*=\s*https?://",
        r"(?:file|page|include)\s*=\s*ftp://",
        r"(?:file|page|include)\s*=\s*php://",
    ]


class WebshellAccessRule(ThreatRule):
    name = "webshell_access"
    category = "remote_code_execution"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Access to known webshell paths"
    check_fields = ["uri_path"]
    patterns = [
        r"/(?:cmd|shell|c99|r57|wso|b374k|alfa|mini)\.(?:php|asp|aspx|jsp|cgi)",
        r"/(?:uploads?|tmp|temp|cache|images?)/[^/]*\.(?:php|asp|aspx|jsp)\b",
        r"[?&]cmd=",
        r"[?&]exec=",
    ]


class ArbitraryFileReadRule(ThreatRule):
    name = "arbitrary_file_read"
    category = "arbitrary_file_read"
    family = ThreatFamily.PATH_FILE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Arbitrary file read via parameter manipulation"
    check_fields = ["uri_path", "uri_query"]
    patterns = [
        r"(?:download|read|view|get|fetch|open|load)\s*[?&=]\s*(?:\.\./|/)",
        r"[?&](?:filename|filepath|path|file|name|doc)\s*=\s*(?:\.\./|/(?:etc|var|tmp|proc))",
    ]


INFO_LEAKAGE_RULES = [
    SensitiveFileExposureRule,
    BackupFileHuntingRule,
    SourceCodeExposureRule,
    DebugEndpointExposureRule,
    ErrorDetailDisclosureRule,
    TechFingerprintingRule,
    APISchemaDiscoveryRule,
    HardcodedCredsInURLRule,
    HardcodedSecretPatternRule,
    DataExfiltrationBasicRule,
    DataExfiltrationLowSlowRule,
]

PATH_FILE_RULES = [
    PathTraversalRule,
    LFIRule,
    RFIRule,
    WebshellAccessRule,
    ArbitraryFileReadRule,
]
