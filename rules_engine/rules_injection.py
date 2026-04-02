"""Family 1: Web Application Injection Attack Rules (13 rules)"""

from __future__ import annotations

from rules_engine.base_rule import ThreatRule
from rules_engine.models import ThreatSeverity, ThreatFamily


class SQLInjectionRule(ThreatRule):
    name = "sql_injection"
    category = "sql_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "SQL injection attempt detected"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?:'|\%27)\s*(?:OR|AND)\s+\d+=\d+",
        r"(?:UNION\s+(?:ALL\s+)?SELECT)",
        r"(?:;\s*DROP\s+(?:TABLE|DATABASE))",
        r"(?:;\s*(?:DELETE|INSERT|UPDATE)\s+)",
        r"(?:extractvalue|updatexml)\s*\(",
        r"(?:LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)",
        r"(?:information_schema\.)",
        r"(?:CONCAT\s*\(.*SELECT)",
        r"(?:0x[0-9a-fA-F]{8,})",
        r"(?:/\*(?:.*?)\*/)",
    ]


class BlindSQLInjectionRule(ThreatRule):
    name = "blind_sql_injection"
    category = "blind_sql_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.92
    description = "Blind SQL injection attempt detected"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?:SLEEP|PG_SLEEP)\s*\(\s*\d+\s*\)",
        r"(?:WAITFOR\s+DELAY\s+'?\d{1,2}:\d{1,2}:\d{1,2}'?)",
        r"(?:BENCHMARK\s*\(\s*\d{3,}\s*,)",
        r"(?:IF\s*\(\s*(?:ASCII|SUBSTRING|MID|ORD|LENGTH)\s*\()",
        r"(?:CASE\s+WHEN\s+.+\s+THEN\s+SLEEP\s*\()",
        r"(?:AND|OR)\s+\(?\s*(?:SELECT|EXISTS\s*\()",
    ]


class XSSRule(ThreatRule):
    name = "xss"
    category = "cross_site_scripting"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.9
    description = "Cross-site scripting attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r"(?:on(?:error|load|click|mouseover|focus|blur|submit|change))\s*=",
        r"alert\s*\(",
        r"eval\s*\(",
        r"document\.(?:cookie|write|location)",
        r"<\s*(?:img|svg|iframe|object|embed)\s+[^>]*(?:on\w+|src)\s*=",
        r"(?:fromCharCode|String\.fromCharCode)",
        r"(?:atob|btoa)\s*\(",
    ]


class SSTIRule(ThreatRule):
    name = "ssti"
    category = "server_side_template_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Server-side template injection attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}",
        r"\{\{\s*config\s*\}\}",
        r"\{%\s*import\s",
        r"\$\{\d+\s*\*\s*\d+\}",
        r"#\{.*\}",
        r"\{\{.*__class__.*\}\}",
        r"\{\{.*__mro__.*\}\}",
    ]


class CommandInjectionRule(ThreatRule):
    name = "os_command_injection"
    category = "os_command_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "OS command injection attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?i)((;\s*(whoami|id|uname|cat|ls|bash|sh|shell_exec))|&&|\||`|\$\(|invoke-webrequest|iex|downloadstring|wget|curl|webclient|powershell|\.exe).*powershell(?:\.exe)?",
        r"(?i)\bshell_exec\s*\(",
    ]


class LDAPInjectionRule(ThreatRule):
    name = "ldap_injection"
    category = "ldap_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "LDAP injection attempt"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"\)\s*\(\s*\|", r"\*\)\s*\(", r"\|\s*\(\s*&\s*\("]


class XPathInjectionRule(ThreatRule):
    name = "xpath_injection"
    category = "xpath_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "XPath injection attempt"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"'\s*or\s+'1'\s*=\s*'1", r"string\s*\(\s*//", r"count\s*\(\s*//"]


class XXERule(ThreatRule):
    name = "xxe"
    category = "xml_external_entity"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.9
    description = "XML External Entity injection"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"<!ENTITY",
        r"<!DOCTYPE[^>]*SYSTEM",
        r"SYSTEM\s+[\"'](?:file|http|ftp|php|expect)://",
    ]


class HTTPParamPollutionRule(ThreatRule):
    name = "http_param_pollution"
    category = "http_parameter_pollution"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.MEDIUM
    confidence = 0.6
    description = "HTTP parameter pollution"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"(?:\?|&)(\w+)=.*?&\1="]


class InsecureDeserializationRule(ThreatRule):
    name = "insecure_deserialization"
    category = "insecure_deserialization"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.85
    description = "Insecure deserialization markers"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"rO0AB",
        r"aced0005",
        r"O:\d+:\"",
        r"__reduce__",
        r"pickle\.loads",
        r"java\.lang\.Runtime",
    ]


class SSRFRule(ThreatRule):
    name = "ssrf"
    category = "server_side_request_forgery"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.85
    description = "Server-side request forgery attempt"
    check_fields = ["uri_path", "uri_query", "original_message"]
    patterns = [
        r"(?:url|uri|path|file|src|href|redirect|proxy|fetch)\s*=\s*(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
        r"(?:url|uri|path|file|src)\s*=\s*(?:https?://)?169\.254\.169\.254",
        r"(?:url|uri|path|file|src)\s*=\s*file:///",
        r"/latest/meta-data",
        r"/computeMetadata/v1",
    ]


class PrototypePollutionRule(ThreatRule):
    name = "prototype_pollution"
    category = "prototype_pollution"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.HIGH
    confidence = 0.8
    description = "Prototype pollution attempt"
    check_fields = ["uri_path", "uri_query"]
    patterns = [r"__proto__", r"constructor\.prototype"]


class ExpressionLanguageInjectionRule(ThreatRule):
    name = "expression_language_injection"
    category = "expression_language_injection"
    family = ThreatFamily.INJECTION
    severity = ThreatSeverity.CRITICAL
    confidence = 0.95
    description = "Expression Language / JNDI injection (includes Log4Shell)"
    check_fields = ["uri_path", "uri_query", "user_agent", "referrer", "original_message"]
    patterns = [
        r"\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds|http)s?://",
        r"\$\{env:",
        r"\$\{sys:",
        r"\$\{java:",
        r"T\(java\.lang\.Runtime\)",
        r"\$\{\$\{",
    ]


INJECTION_RULES = [
    SQLInjectionRule,
    BlindSQLInjectionRule,
    XSSRule,
    SSTIRule,
    CommandInjectionRule,
    LDAPInjectionRule,
    XPathInjectionRule,
    XXERule,
    HTTPParamPollutionRule,
    InsecureDeserializationRule,
    SSRFRule,
    PrototypePollutionRule,
    ExpressionLanguageInjectionRule,
]
