"""Families 7, 8, 9: Bot/Scanner (6) + Rate/DoS (6) + CVE (5)"""

from __future__ import annotations

from typing import Any, Optional
from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent
from collections import defaultdict
import ipaddress

# Family 7: Bot & Scanner

class KnownScannerUARule(ThreatRule):
    name = "known_scanner_ua"
    category = "recon_scanner"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.95
    description = "Known vulnerability scanner user agent"
    check_fields = ["user_agent"]
    patterns = [
        r"(?:sqlmap|nikto|nmap|nessus|openvas|masscan|zap(?:proxy)?|skipfish|w3af|arachni)",
        r"(?:burp(?:suite)?|qualys|acunetix|appscan|webinspect|netsparker|invicti)",
        r"(?:dirbuster|dirb|gobuster|wfuzz|ffuf|feroxbuster)",
        r"(?:nuclei|subfinder|amass|httpx|dalfox|tplmap|commix|hydra)",
        r"(?:masscan|zgrab|censys|shodan)",
    ]


class HeadlessBrowserRule(ThreatRule):
    name = "headless_browser"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Headless browser or automation tool"
    check_fields = ["user_agent"]
    patterns = [
        r"(?i)\bHeadlessChrome\/\d+(?:\.\d+){1,3}\b.*\b(curl|wget|python|libwww|java|requests)\b|(?:^|\s)HeadlessChrome\/\d+(?:\.\d+){1,3}\b(?:\s*$)",
        r"PhantomJS",
        r"(?:Selenium|webdriver|Playwright)",
        r"Puppeteer",
        r"(?:Cypress|Nightwatch|Robot Framework)",
    ]


class Rapid404Rule(RateBasedRule):
    name = "rapid_404_generation"
    category = "recon_scanner"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Rapid 404 generation (directory brute-forcing)"
    threshold = 50

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        # Check for Public IP only
        try:
            ip = ipaddress.ip_address(group_key)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return None
        except ValueError:
            pass

        not_found = [ev for ev in events if ev.http_status == 404]
        successes = [ev for ev in events if ev.http_status == 200]

        # Should contain only 404 and zero (or <= 1 200 return code)
        if len(successes) > 1:
            return None

        unique_uris = {ev.uri_path for ev in not_found if ev.uri_path}
        if len(unique_uris) >= self.threshold:
            last = not_found[-1]
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(unique_uris)} unique 404s from {group_key} on {last.uri_path} (successes: {len(successes)})",
                matched_field="http_status",
                uri=last.uri_path,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            )
        return None


class ContentScrapingRule(RateBasedRule):
    name = "content_scraping"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Systematic content scraping"
    threshold = 200

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        # Skip private/internal IPs
        ip = group_key
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return None
        except ValueError:
            pass
        
        ok_evts = [ev for ev in events if ev.http_status and 200 <= ev.http_status < 300]
        uris = {ev.uri_path for ev in ok_evts if ev.uri_path}
        if len(uris) >= self.threshold:
            last = ok_evts[-1] if ok_evts else events[-1]
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(uris)} unique URIs from {group_key} (sample: {last.uri_path})",
                matched_field="uri_path",
                uri=last.uri_path,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            )
        return None


class FakeSearchBotRule(ThreatRule):
    name = "fake_search_bot"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "Fake search engine bot"
    check_fields = ["user_agent"]
    patterns = [r"(?:Googlebot|Bingbot|baiduspider|YandexBot)(?!/)"]


class MaliciousBotSignatureRule(ThreatRule):
    name = "malicious_bot_signature"
    category = "bot_automation"
    family = ThreatFamily.BOT_SCANNER
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Known malicious bot signature"
    check_fields = ["user_agent"]
    patterns = [
        r"(?:Morfeus|ZmEu|Muieblackcat|AutoPwn)",
        r"(?:DirBuster|Gobuster|Dirsearch)",
        r"(?:WhatWeb|BlindElephant)",
    ]


# Family 8: Rate & DoS

class HTTPFloodRule(RateBasedRule):
    name = "http_flood"
    category = "rate_limiting"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "HTTP flood: extremely high request rate"
    threshold = 500

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        if len(events) >= self.threshold:
            return ThreatMatch(
                event_id=events[-1].event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(events)} requests from {group_key} in batch (target: {events[-1].uri_path})",
                matched_field="rate",
                uri=events[-1].uri_path,
                timestamp=events[-1].timestamp,
                src_ip=events[-1].src_ip,
            )
        return None


class RateLimitBypassHeaderRule(ThreatRule):
    name = "rate_limiting_bypass_headers"
    category = "rate_limiting_bypass"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Rate limiting bypass probe via spoofed client identity headers"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?:X-Forwarded-For|X-Real-IP|X-Client-IP|True-Client-IP|CF-Connecting-IP)\s*:",
        r"(?:Forwarded)\s*:\s*for=",
        r"[?&](?:x_forwarded_for|x_real_ip|client_ip|forwarded|true_client_ip)\s*=",
    ]


class RateLimitBypassAfterThrottleRule(RateBasedRule):
    name = "rate_limiting_bypass_after_429"
    category = "rate_limiting_bypass"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "Sustained request bursts despite repeated HTTP 429 throttling"
    threshold = 60

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        if len(events) < self.threshold:
            return None

        throttled = [ev for ev in events if ev.http_status == 429]
        if len(throttled) < 3:
            return None

        continued = [ev for ev in events if ev.http_status and ev.http_status != 429]
        if len(continued) < self.threshold:
            return None

        last = events[-1]
        return ThreatMatch(
            event_id=last.event_id,
            rule_name=self.name,
            category=self.category,
            family=self.family,
            severity=self.severity,
            confidence=self.confidence,
            evidence=f"{len(events)} requests with {len(throttled)} HTTP 429 responses from {group_key} (target: {last.uri_path})",
            matched_field="http_status",
            uri=last.uri_path,
            timestamp=last.timestamp,
            src_ip=last.src_ip,
        )


class SlowlorisRule(RateBasedRule):
    name = "slowloris_suspected"
    category = "denial_of_service"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.7
    description = "Slowloris attack suspected: multi-factor scoring"
    threshold = 100

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        if not events:
            return None
            
        # Consider only public IPs
        try:
            ip = ipaddress.ip_address(group_key)
            if not ip.is_global:
                return None
        except ValueError:
            return None

        unique_uris = {ev.uri_path for ev in events if ev.uri_path}
        
        if len(unique_uris) >= self.threshold:
            last = events[-1]
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"Slowloris suspected: {len(unique_uris)} unique URIs hit from public IP {group_key}",
                matched_field="uri_path",
                uri=last.uri_path,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            )
        return None


class APIRateAbuseRule(RateBasedRule):
    name = "api_rate_abuse"
    category = "rate_limiting"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.7
    description = "API rate abuse"
    threshold = 300

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        uri_counts = defaultdict(int)
        last_ev_by_uri = {}
        
        for ev in events:
            uri = (ev.uri_path or "").lower()
            if "/api/" in uri:
                uri_counts[uri] += 1
                last_ev_by_uri[uri] = ev
        
        if not uri_counts:
            return None
            
        # Check if same src hits SAME uri >= threshold
        for uri, count in uri_counts.items():
            if count >= self.threshold:
                last = last_ev_by_uri[uri]
                return ThreatMatch(
                    event_id=last.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"API rate abuse from {group_key} targeting {uri} ({count} requests)",
                    matched_field="uri_path",
                    uri=last.uri_path,
                    timestamp=last.timestamp,
                    src_ip=last.src_ip,
                )
        return None


class ResourceExhaustionRule(RateBasedRule):
    name = "resource_exhaustion"
    category = "denial_of_service"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "Repeated hits to expensive endpoints"
    threshold = 30
    _EXPENSIVE = [
        r"^/search(/|$)",
        r"^/export(/|$)",
        r"^/report(/|$)",
        r"^/download(/|$)",
        r"^/generate(/|$)",
        r"^/process(/|$)"
    ]

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        import re
        hits = 0
        last = None
        for ev in events:
            uri = (ev.uri_path or "").lower()
            if any(re.search(ep, uri) for ep in self._EXPENSIVE):
                hits += 1
                last = ev
        if hits >= self.threshold and last:
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{hits} expensive endpoint hits from {group_key} (last: {last.uri_path})",
                matched_field="uri_path",
                uri=last.uri_path,
                timestamp=last.timestamp,
                src_ip=last.src_ip,
            )
        return None


# Family 9: CVE Exploits

class Log4ShellRule(ThreatRule):
    name = "log4shell_cve_2021_44228"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Log4Shell (CVE-2021-44228) JNDI injection"
    check_fields = ["uri_path", "uri_query", "user_agent", "referrer", "original_message"]
    patterns = [r"\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://"]


class Spring4ShellRule(ThreatRule):
    name = "spring4shell_cve_2022_22965"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Spring4Shell (CVE-2022-22965)"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"class\.module\.classLoader", r"class%5B%5D"]


class ShellshockRule(ThreatRule):
    name = "shellshock_cve_2014_6271"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Shellshock (CVE-2014-6271)"
    check_fields = ["user_agent", "referrer", "original_message"]
    patterns = [r"\(\)\s*\{.*;\s*\}\s*;"]


class ApacheStrutsRCERule(ThreatRule):
    name = "apache_struts_rce"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "Apache Struts OGNL injection / RCE"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [r"%\{.*#_memberAccess", r"ognl\.OgnlContext"]


class PHPSpecificAttackRule(ThreatRule):
    name = "php_specific_attack"
    category = "cve_exploit"
    family = ThreatFamily.CVE_EXPLOIT
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "PHP-specific attack patterns"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"php://(?:input|filter|data|expect)",
        r"/cgi-bin/.*\.(?:cgi|pl|py|sh)",
        r"<\?php",
        r"assert\s*\(",
        r"base64_decode\s*\(",
        r"system\s*\(",
        r"passthru\s*\(",
    ]


BOT_SCANNER_RULES = [
    KnownScannerUARule,
    HeadlessBrowserRule,
    Rapid404Rule,
    ContentScrapingRule,
    FakeSearchBotRule,
    MaliciousBotSignatureRule,
]

RATE_DOS_RULES = [
    HTTPFloodRule,
    RateLimitBypassHeaderRule,
    RateLimitBypassAfterThrottleRule,
    SlowlorisRule,
    APIRateAbuseRule,
    ResourceExhaustionRule,
]

CVE_EXPLOIT_RULES = [
    Log4ShellRule,
    Spring4ShellRule,
    ShellshockRule,
    ApacheStrutsRCERule,
    PHPSpecificAttackRule,
]
