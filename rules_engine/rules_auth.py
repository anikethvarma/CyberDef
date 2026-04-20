"""
Family 2: Authentication, Session & Access Control Rules (9 rules)
"""

from __future__ import annotations
import re
from urllib.parse import urlparse
from typing import Any, Optional

from rules_engine.base_rule import ThreatRule, RateBasedRule
from rules_engine.models import ThreatMatch, ThreatSeverity, ThreatFamily
from shared_models.events import NormalizedEvent


class BruteForceLoginRule(RateBasedRule):
    """
    Brute force login detection with dual threshold based on IP scope.

    Public IP  (is_private=False): >=20 failures, 0 successes → HIGH
    Private IP (is_private=True):  >=50 failures, 0 successes → MEDIUM

    Zero-success gate: if any 200 OK was seen on an auth URI within
    the group, the rule does not fire to avoid false positives on
    legitimate slow credential rotation or account unlock flows.
    """
    name = "brute_force_login"
    category = "broken_authentication"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH  # overridden per IP scope below
    confidence = 0.85
    description = "Brute force login: repeated auth failures with zero success from same IP"
    threshold = 20  # public IP default; private uses 50

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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
        import ipaddress

        # --- Determine IP scope ---
        try:
            is_private = ipaddress.ip_address(group_key).is_private
        except ValueError:
            is_private = False

        threshold = 50 if is_private else 20
        severity  = ThreatSeverity.MEDIUM if is_private else ThreatSeverity.HIGH

        auth_failures = 0
        success_count = 0
        last_event = None

        for ev in events:
            if ev.http_status and ev.http_status in (401, 403):
                uri = (ev.uri_path or "").lower()
                if any(p in uri for p in self._AUTH_PATHS) or ev.http_status == 401:
                    auth_failures += 1
                    last_event = ev
            elif ev.http_status == 200:
                # Track successful logins on auth URIs — used as zero-success gate
                uri = (ev.uri_path or "").lower()
                if any(p in uri for p in self._AUTH_PATHS):
                    success_count += 1

        # Hard gate: any successful auth in this batch → do not flag as brute force
        if success_count > 0:
            return None

        if auth_failures >= threshold and last_event:
            return ThreatMatch(
                event_id=last_event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=severity,
                confidence=self.confidence,
                evidence=(
                    f"{auth_failures} auth failures from {group_key} "
                    f"({'private' if is_private else 'public'} IP, threshold={threshold})"
                ),
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
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

    def check_group(self, events: list[NormalizedEvent], group_key: str) -> Optional[ThreatMatch]:
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
        r"(([?&;])(JSESSIONID|PHPSESSID|sessionid|sessid|sid|ASPSESSIONID)=[a-z0-9\-]{8,}|;jsessionid=[a-z0-9\-]{8,})",
    ]


class JWTManipulationRule(ThreatRule):
    name = "jwt_manipulation"
    category = "jwt_manipulation"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.HIGH
    confidence = 0.75
    description = "JWT token manipulation attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        checkfields = [event.uri_path, event.uri_query, event.original_message]
        #jwt_exclude = r"(?i)ScormEngineInterface"
        if not any(re.search( r"(?i)ScormEngineInterface", f or "") for f in checkfields):
            patterns = [ r"(?i)(eyJ[^.]*ImFsZyI6Im5vbmUifQ|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.\b|(GET|POST).*?(token=|jwt=|auth=).*?eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)",
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
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Privilege escalation attempt via shell commands, SUID bits, or known tooling"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?i)((;\s*|\|\||&&|\|)\s*(sudo|su|chmod|chown|setcap))\b|(cmd=|exec=|system=).*(sudo|su|chmod|chown)\b|chmod\s+[0-7]*4[0-7]{2}|\bsu\s+-?\s*root\b|bash\s+-p|sh\s+-p|python.*pty\.spawn|/etc/(sudoers|shadow)|setcap\s+|(?:\s*\./|\s*/tmp/|\s*/dev/shm/).*(linpeas|pspy|linenum)",
    ]


class CSRFIndicatorRule(ThreatRule):
    name = "csrf_indicator"
    category = "csrf"
    family = ThreatFamily.AUTH_ACCESS
    severity = ThreatSeverity.MEDIUM
    confidence = 0.5
    description = "CSRF indicator: state-changing request with suspicious referer and missing token"
    check_fields = ["uri_query", "original_message"]
    
    BASE_DOMAIN = "ultimatix.net"

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
        if event.http_method not in ("POST", "PUT", "DELETE", "PATCH"):
            return None

        referrer = event.referrer or ""
        if not referrer or not referrer.startswith("http"):
            return None
        
        ref_host = urlparse(referrer).hostname
        if not ref_host:
            return None
            
        ref_host = ref_host.lower()
        
        # Domain exclusions
        if (ref_host.endswith("tcsapps.com") or 
            "microsoftonline.com" in ref_host or 
            "s1-eu.ariba.com" in ref_host or 
            ref_host == "t.mediassist.in"):
            return None

        base_domain = self.BASE_DOMAIN.lower()
        
        is_same_site = ref_host == base_domain or ref_host.endswith(f".{base_domain}")
        cross_origin = not is_same_site
        
        log_surface = " ".join(filter(None, [event.uri_query, event.original_message]))
        has_token = bool(re.search(r'(token|auth|state|session)=', log_surface, re.I))
        missing_token = not has_token
        
        if cross_origin and missing_token:
            return ThreatMatch(
                event_id=event.event_id,
                rule_name=self.name,
                category=self.category,
                family=self.family,
                severity=self.severity,
                confidence=self.confidence,
                evidence=f"{event.http_method} cross-origin from {referrer[:100]} with missing token",
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

    def match(self, event: NormalizedEvent) -> Optional[ThreatMatch]:
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
