"""
Family 2: Authentication, Session & Access Control Rules (9 rules)
"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class BruteForceLoginRule(RateBasedRule):
    name = "brute_force_login"
    category = "broken_authentication"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Brute force login: >10 auth failures from same IP in batch"
    threshold = 10

    _AUTH_PATHS = {
        "/login",
        "/signin",
        "/auth",
        "/api/auth",
        "/wp-login",
        "/admin/login",
        "/j_security_check",
        "/Account/Login",
        "/oauth/token",
    }

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        auth_failures = 0
        last_event = None
        for ev in events:
            if ev.http_status and ev.http_status in (401, 403):
                uri = (ev.uri_path or "").lower()
                if any(p in uri for p in self._AUTH_PATHS) or ev.http_status == 401:
                    auth_failures += 1
                    last_event = ev
        if auth_failures >= self.threshold and last_event:
            return ThreatMatch(
                event_id=last_event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{auth_failures} auth failures from {group_key}",
                matched_field="http_status",
                timestamp=last_event.timestamp,
                src_ip=last_event.src_ip,
            )
        return None


class CredentialStuffingRule(RateBasedRule):
    name = "credential_stuffing"
    category = "broken_authentication"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Credential stuffing: many distinct login attempts from same IP"
    threshold = 20

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        login_401s = [ev for ev in events if ev.http_status == 401]
        if len(login_401s) >= self.threshold:
            return ThreatMatch(
                event_id=login_401s[-1].event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(login_401s)} 401 responses from {group_key}",
                matched_field="http_status",
                timestamp=login_401s[-1].timestamp,
                src_ip=login_401s[-1].src_ip,
            )
        return None


class AuthenticationFailuresRule(RateBasedRule):
    name = "authentication_failures"
    category = "authentication_failures"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.75
    description = "Repeated authentication failures from same source"
    threshold = 8

    _AUTH_HINTS = {
        "/login",
        "/signin",
        "/auth",
        "/oauth",
        "/session",
        "/token",
        "/password",
    }

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> ThreatMatch | None:
        failures: list[NormalizedEvent] = []
        for ev in events:
            if ev.http_status not in (401, 403):
                continue
            uri = (ev.uri_path or "").lower()
            has_auth_hint = any(hint in uri for hint in self._AUTH_HINTS)
            if has_auth_hint or ev.username:
                failures.append(ev)

        if len(failures) >= self.threshold:
            last_event = failures[-1]
            return ThreatMatch(
                event_id=last_event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{len(failures)} authentication failures from {group_key}",
                matched_field="http_status",
                timestamp=last_event.timestamp,
                src_ip=last_event.src_ip,
            )
        return None


class SessionFixationRule(ThreatRule):
    name = "session_fixation"
    category = "session_fixation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Session fixation attempt - session IDs in URL"
    check_fields = ["uri_path", "uri_query"]
    patterns = [
        r"(?:JSESSIONID|PHPSESSID|sessionid|sid|session_id|ASPSESSIONID)\s*=",
    ]


class JWTManipulationRule(ThreatRule):
    name = "jwt_manipulation"
    category = "jwt_manipulation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "JWT token manipulation attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?i)^(?!.*ScormEngineInterface).*(eyJ[^.]*ImFsZyI6Im5vbmUifQ|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.\b|(GET|POST).*(token=|jwt=|auth=).*eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)",
    ]


class IDORRule(ThreatRule):
    name = "idor"
    category = "idor"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "IDOR: sequential ID enumeration in API paths"
    check_fields = ["uri_path"]
    patterns = [
        r"/api/(?:v\d+/)?(?:users?|accounts?|profiles?|orders?|invoices?)/\d{1,8}(?:/|$)",
    ]


class PrivilegeEscalationRule(ThreatRule):
    name = "privilege_escalation_probe"
    category = "privilege_escalation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.7
    description = "Privilege escalation probing"
    check_fields = ["uri_path", "uri_query"]
    patterns = [
        r"[?&](?:role|is_admin|admin|isAdmin|privilege|access_level)\s*=",
        r"/(?:su|sudo|superuser|root|superadmin)\b",
    ]


class CSRFIndicatorRule(ThreatRule):
    name = "csrf_indicator"
    category = "csrf"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "CSRF indicator: state-changing request with suspicious referer"
    check_fields = []

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        if event.http_method not in ("POST", "PUT", "DELETE", "PATCH"):
            return None

        referrer = event.referrer or ""
        dst_host = event.dst_host or ""
        if referrer and dst_host:
            if dst_host not in referrer and referrer.startswith("http"):
                return ThreatMatch(
                    event_id=event.event_id,
                    rule_name=self.name,
                    category=self.category,
                    family=self.family,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=f"{event.http_method} with external referer: {referrer[:100]}",
                    matched_field="referrer",
                    timestamp=event.timestamp,
                    src_ip=event.src_ip,
                )
        return None


class BrokenFunctionAuthRule(ThreatRule):
    name = "broken_function_auth"
    category = "broken_function_level_auth"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.6
    description = "Successful access to admin/management endpoints"
    check_fields = []

    _ADMIN_PATHS = [
        "/admin",
        "/manager",
        "/management",
        "/console",
        "/dashboard/admin",
        "/api/admin",
        "/superadmin",
        "/wp-admin/admin-ajax",
    ]

    def match(self, event: NormalizedEvent) -> ThreatMatch | None:
        uri = (event.uri_path or "").lower()
        if event.http_status and 200 <= event.http_status < 300:
            for path in self._ADMIN_PATHS:
                if uri.startswith(path):
                    return ThreatMatch(
                        event_id=event.event_id,
                        rule_name=self.name,
                        category=self.category,
                        family=self.family,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=f"200 OK on admin path: {uri[:100]}",
                        matched_field="uri_path",
                        timestamp=event.timestamp,
                        src_ip=event.src_ip,
                    )
        return None


AUTH_ACCESS_RULES = [
    BruteForceLoginRule,
    CredentialStuffingRule,
    AuthenticationFailuresRule,
    SessionFixationRule,
    JWTManipulationRule,
    IDORRule,
    PrivilegeEscalationRule,
    CSRFIndicatorRule,
    BrokenFunctionAuthRule,
]
