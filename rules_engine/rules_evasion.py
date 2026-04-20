"""Family 6: Evasion, Cache & Redirect Rules"""

from __future__ import annotations
from typing import Optional
import re
import ipaddress
from urllib.parse import urlsplit, unquote

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class OpenRedirectRule(ThreatRule):
    name = "open_redirect"
    category = "open_redirect"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.8
    description = "Open redirect via URL parameter"
    check_fields = []

    _PARAM_RE = re.compile(
        r"(?:^|[?&])(?:redirect|url|next|return|goto|continue|dest|destination|redir|returnUrl|target|forward)\s*=\s*([^&\s]+)",
        re.IGNORECASE,
    )
    _LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "www.ultimatix.net"}

    def _is_external_redirect_target(self, raw_target: str) -> bool:
        target = unquote(raw_target).strip()
        if not target:
            return False

        if target.startswith("//"):
            return True

        if not (target.startswith("http://") or target.startswith("https://")):
            return False

        parsed = urlsplit(target)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if host in self._LOCAL_HOSTS:
            return False

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass

        return True

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        search_surface = " ".join(filter(None, [event.uri_query, event.original_message]))
        if not search_surface:
            return None

        m = self._PARAM_RE.search(search_surface)
        if not m:
            return None

        target = m.group(1)
        if self._is_external_redirect_target(target):
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"Open redirect to external target: {target[:100]}",
                matched_field="uri_query",
                timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None


class CacheDeceptionRule(ThreatRule):
    name = "cache_deception"
    category = "cache_deception"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Cache deception attempt"
    check_fields = ["uri_path"]
    patterns = [
        r"/account.*\.(?:css|js|jpg|png|gif|ico)",
        r"/profile.*\.(?:css|js|jpg|png|gif|ico)",
        r"/admin.*\.(?:css|js|jpg|png|gif|ico)",
    ]


class CachePoisoningRule(ThreatRule):
    name = "cache_poisoning"
    category = "cache_poisoning"
    family = ThreatFamily.CACHE_REDIRECT
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Cache poisoning probe"
    check_fields = ["original_message"]
    patterns = [
        r"X-Forwarded-Host\s*:",
        r"X-Original-URL\s*:",
        r"X-Rewrite-URL\s*:",
    ]

class DoubleURLEncodingRule(ThreatRule):
    name = "double_url_encoding"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Double URL encoding to bypass WAF/filters"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%25[0-9a-fA-F]{2}", r"%252[fFcCeE]", r"%2527"]


class NullByteInjectionRule(ThreatRule):
    name = "null_byte_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Null byte injection"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%00", r"\\x00"]


class CRLFInjectionRule(ThreatRule):
    name = "crlf_injection"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "CRLF injection for header manipulation"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%0[dD]%0[aA]", r"\\r\\n", r"%0[aA](?:Set-Cookie|Location|Content-Type):"]


class UnicodeAbuseRule(ThreatRule):
    name = "unicode_abuse"
    category = "insecure_input_validation"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "Unicode/UTF-8 overlong sequences"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"%c0%af", r"%c1%9c", r"%e0%80%af", r"%u00[0-9a-fA-F]{2}"]


class HTTPVerbTamperingRule(ThreatRule):
    name = "http_verb_tampering"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Unusual HTTP methods"
    check_fields = []
    _UNUSUAL = {"TRACE", "CONNECT", "PROPFIND", "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK"}

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        method = (event.http_method or "").upper()
        if method in self._UNUSUAL:
            return ThreatMatch(
                event_id=event.event_id, rule_name=self.name,
                category=self.category, family=self.family,
                severity=self.severity, confidence=self.confidence,
                evidence=f"Unusual HTTP method: {method}",
                matched_field="http_method", timestamp=event.timestamp,
                src_ip=event.src_ip,
            )
        return None


class PathNormalizationBypassRule(ThreatRule):
    name = "path_normalization_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.7
    description = "Path normalization bypass"
    check_fields = ["uri_path"]
    patterns = [r"//+", r"/\./", r"/;/", r"\\\\"]


class WAFBypassRule(ThreatRule):
    name = "waf_bypass"
    category = "evasion"
    family = ThreatFamily.EVASION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "WAF bypass via comment/case tricks"
    check_fields = ["uri_path", "uri_query", "original_message"]

CACHE_REDIRECT_RULES = [
    OpenRedirectRule,
    CacheDeceptionRule,
    CachePoisoningRule,
]

EVASION_RULES = [
    DoubleURLEncodingRule, NullByteInjectionRule, CRLFInjectionRule,
    UnicodeAbuseRule, HTTPVerbTamperingRule, PathNormalizationBypassRule, WAFBypassRule,
]
