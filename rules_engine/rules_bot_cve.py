"""Families 7, 8, 9: Bot/Scanner (6) + Rate/DoS (6) + CVE (5)"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        not_found = [ev for ev in events if ev.http_status == 404]
        if len(not_found) >= self.threshold:
            last = not_found[-1]
            return ThreatMatch(
                event_id=last.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(not_found)} 404s from {group_key}",
                matched_field="http_status",
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
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
                evidence=f"{len(uris)} unique URIs from {group_key}",
                matched_field="uri_path",
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        if len(events) >= self.threshold:
            return ThreatMatch(
                event_id=events[-1].event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(events)} requests from {group_key} in batch",
                matched_field="rate",
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
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
            evidence=f"{len(events)} requests with {len(throttled)} HTTP 429 responses from {group_key}",
            matched_field="http_status",
            timestamp=last.timestamp,
            src_ip=last.src_ip,
        )


class SlowlorisRule(ThreatRule):
    name = "slowloris_indicator"
    category = "denial_of_service"
    family = ThreatFamily.RATE_DOS
    severity = ThreatSeverity.HIGH
    confidence = 0.5
    description = "Slowloris indicator: very long request"
    check_fields = []

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if event.duration_ms and event.duration_ms > 30000:
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"Request took {event.duration_ms}ms",
                matched_field="duration_ms",
                timestamp=event.timestamp,
                src_ip=event.src_ip,
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        api_evts = [ev for ev in events if ev.uri_path and "/api/" in ev.uri_path.lower()]
        if len(api_evts) >= self.threshold:
            return ThreatMatch(
                event_id=api_evts[-1].event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(api_evts)} API requests from {group_key}",
                matched_field="rate",
                timestamp=api_evts[-1].timestamp,
                src_ip=api_evts[-1].src_ip,
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
    _EXPENSIVE = ["/search", "/export", "/report", "/download", "/generate", "/process"]

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        hits = 0
        last = None
        for ev in events:
            uri = (ev.uri_path or "").lower()
            if any(ep in uri for ep in self._EXPENSIVE):
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
                evidence=f"{hits} expensive endpoint hits from {group_key}",
                matched_field="uri_path",
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
