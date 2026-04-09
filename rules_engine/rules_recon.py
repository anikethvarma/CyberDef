from typing import Optional
"""Families 3 & 4: Information Leakage & Recon (11) + Path & File Access (5)"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class SensitiveFileExposureRule(ThreatRule):
    name = "sensitive_file_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Access to sensitive config/credential files"
    check_fields = ["uri_path"]
    patterns = [
        r"(?:/\.env|/\.env\.local|/\.env\.prod)",
        r"/wp-config\.php",
        r"/config\.yml|/config\.yaml|/config\.json",
        r"/application\.properties|/application\.yml",
        r"/\.htpasswd|/\.htaccess",
        r"/web\.config",
    ]


class BackupFileHuntingRule(ThreatRule):
    name = "backup_file_hunting"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Probing for backup/archive files"
    check_fields = ["uri_path"]
    patterns = [
        r"\.(?:bak|old|orig|copy|save|swp|tmp|temp)(?:\?|$)",
        r"\.(?:sql|dump|tar|gz|zip|rar|7z)(?:\?|$)",
        r"~$",
    ]


class SourceCodeExposureRule(ThreatRule):
    name = "source_code_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Access to source code repo files"
    check_fields = ["uri_path"]
    patterns = [
        r"/\.git/(?:HEAD|config|index|objects|refs)",
        r"/\.svn/(?:entries|wc\.db)",
        r"/\.hg/",
        r"/\.DS_Store",
        r"/\.idea/",
    ]


class DebugEndpointExposureRule(ThreatRule):
    name = "debug_endpoint_exposure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Access to debug/admin endpoints"
    check_fields = ["uri_path"]
    patterns = [
        r"/(?:debug|_debug|trace|_trace)\b",
        r"/actuator(?:/|$)",
        r"/console(?:/|$)",
        r"/phpinfo(?:\.php)?",
        r"/server-(?:status|info)",
        r"/_profiler",
    ]


class ErrorDetailDisclosureRule(ThreatRule):
    name = "error_detail_disclosure"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Large 5xx response possibly containing error details"
    check_fields = []

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
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


class DataExfiltrationPatternRule(ThreatRule):
    name = "data_exfiltration_pattern"
    category = "sensitive_information_disclosure"
    family = ThreatFamily.INFO_LEAKAGE
    severity = ThreatSeverity.HIGH
    confidence = 0.5
    description = "Large data response from sensitive endpoints"
    check_fields = []
    _SENSITIVE = ["/export", "/download", "/dump", "/backup", "/api/users", "/api/data"]

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        uri = (event.uri_path or "").lower()
        resp_size = event.response_size or event.bytes_sent or 0
        if resp_size > 100000:
            for path in self._SENSITIVE:
                if path in uri:
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"Large response ({resp_size}B) from {uri[:80]}",
                        matched_field="uri_path",
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
        return None


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
        r"\.\.\\",
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
    DataExfiltrationPatternRule,
]

PATH_FILE_RULES = [
    PathTraversalRule,
    LFIRule,
    RFIRule,
    WebshellAccessRule,
    ArbitraryFileReadRule,
]
