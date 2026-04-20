"""
Web WAF / Threat Log Parser

Parser for structured security log CSVs that use columns like
SrcIP, DstIP, Action, ThreatType, SeverityLevel - as seen in
the Multiple_threats.csv export format.

Example columns:
    Action, CNAMTime, SrcIP, DstIP, DstPort, Method, ReturnCode,
    URL, UserAgent, SeverityLevel, ThreatType, Indicator, IndicatorType,
    DevSrcIP, DeviceName, Domain, SourceName, SourceType, ...
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


@ParserRegistry.register
class WebWAFParser(BaseParser):
    """
    Parser for web/WAF structured threat logs.

    Handles CSVs where source and destination IPs are stored in
    non-standard column names (SrcIP / DstIP) alongside rich
    threat-intel and HTTP metadata fields.
    """

    name = "web_waf"
    vendor = "web_waf"
    description = "Parser for Web WAF / structured threat log CSVs (SrcIP, DstIP, Action, ThreatType)"

    column_mappings = {
        "src_ip": [
            "SrcIP", "srcip", "src_ip", "source_ip", "SourceIP",
            "DevSrcIP",  # device-level source IP (fallback)
        ],
        "dst_ip": [
            "DstIP", "dstip", "dst_ip", "destination_ip", "DestIP",
        ],
        "dst_port": [
            "DstPort", "dstport", "dst_port", "destination_port", "DestPort",
        ],
        "timestamp": [
            "CNAMTime", "SystemTstamp", "timestamp", "EventTime",
            "log_time", "datetime",
        ],
        "action": [
            "Action", "action", "Status", "status",
        ],
        "method": [
            "Method", "method", "HTTPMethod",
        ],
        "http_status": [
            "ReturnCode", "return_code", "http_status", "StatusCode",
        ],
        "url": [
            "URL", "url", "URI", "uri", "UriQuery",
        ],
        "user_agent": [
            "UserAgent", "user_agent", "useragent", "UA",
        ],
        "referrer": [
            "Referrer", "Referer", "referer", "referrer",
        ],
        "content_type": [
            "ContentType", "content_type", "MimeType",
        ],
        "request_size": [
            "RequestSize", "request_size", "ReqBytes", "BytesIn",
        ],
        "response_size": [
            "ResponseSize", "response_size", "RespBytes", "BytesOut",
        ],
        "severity": [
            "SeverityLevel", "severity_level", "severity", "Priority",
        ],
        "threat_type": [
            "ThreatType", "threat_type", "ThreatCategory",
        ],
        "indicator": [
            "Indicator", "indicator", "Threat", "threat",
        ],
        "indicator_type": [
            "IndicatorType", "indicator_type",
        ],
        "username": [
            "SrcUser", "User", "user", "username", "Principal",
        ],
        "application": [
            "SourceType", "source_type", "SourceName", "application",
        ],
        "device": [
            "DeviceName", "device_name", "DevName",
        ],
        "domain": [
            "Domain", "domain", "Host", "DestDomain",
        ],
    }

    # Columns that strongly indicate this is a Web WAF log
    _REQUIRED_INDICATORS = {"srcip", "dstip"}
    _BONUS_INDICATORS = {"action", "threattype", "severitylevel", "returncode"}

    # ------------------------------------------------------------------ #
    # Detection                                                            #
    # ------------------------------------------------------------------ #

    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """
        Return high confidence when SrcIP + DstIP columns are present.
        Bonus confidence for other WAF-specific columns.
        """
        cols_lower = {c.lower().replace("_", "").replace(" ", "") for c in columns}

        required_hits = _REQUIRED_INDICATORS & cols_lower
        if len(required_hits) < 2:
            return 0.0

        bonus_hits = len(_BONUS_INDICATORS & cols_lower)

        # Base 0.65 for src+dst, up to 0.95 with bonus columns
        confidence = 0.65 + min(bonus_hits * 0.075, 0.30)
        return round(confidence, 3)

    # ------------------------------------------------------------------ #
    # Parsing                                                              #
    # ------------------------------------------------------------------ #

    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse a Web WAF structured log row."""
        data = raw_row.raw_data

        src_ip = self.find_column(data, "src_ip")
        dst_ip = self.find_column(data, "dst_ip")
        dst_port = self._parse_port(self.find_column(data, "dst_port"))

        timestamp = self._parse_timestamp(data)

        action_raw = self.find_column(data, "action")
        action = self._normalize_action(action_raw)

        method = self.find_column(data, "method")
        http_status = self._parse_int(self.find_column(data, "http_status"))
        url = self.find_column(data, "url")
        uri_path, uri_query = self._extract_uri_parts(url)

        user_agent = self.find_column(data, "user_agent")
        referrer = self.find_column(data, "referrer")
        content_type = self.find_column(data, "content_type")
        request_size = self._parse_int(self.find_column(data, "request_size"))
        response_size = self._parse_int(self.find_column(data, "response_size"))

        severity = self.find_column(data, "severity")
        username = self.find_column(data, "username")
        application = self.find_column(data, "application")

        threat_type = self.find_column(data, "threat_type")
        indicator = self.find_column(data, "indicator")
        indicator_type = self.find_column(data, "indicator_type")
        device = self.find_column(data, "device")
        domain = self.find_column(data, "domain")

        vendor_specific: dict[str, Any] = {}
        for k, v in {
            "threat_type": threat_type,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "device": device,
            "domain": domain,
            "raw_action": action_raw,
        }.items():
            if v:
                vendor_specific[k] = str(v)

        serialized_original = " ".join(
            f"{k}={v}"
            for k, v in data.items()
            if v is not None and str(v).strip()
        )

        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=self._clean_ip(src_ip),
            destination_address=self._clean_ip(dst_ip),
            destination_hostname=str(domain) if domain else None,
            destination_port=dst_port,
            protocol="HTTP",
            action=action,
            username=str(username) if username else None,
            application=str(application) if application else None,
            parsed_data={
                "http_method": str(method) if method else None,
                "http_status": http_status,
                "uri_path": uri_path,
                "uri_query": uri_query,
                "user_agent": str(user_agent) if user_agent else None,
                "referrer": str(referrer) if referrer else None,
                "content_type": str(content_type) if content_type else None,
                "request_size": request_size,
                "response_size": response_size,
                "severity": str(severity) if severity else None,
                "original_message": serialized_original,
            },
            vendor_specific=vendor_specific,
        )

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _clean_ip(self, value: Any) -> str | None:
        """Return IP string or None for dash / empty placeholders."""
        if value is None:
            return None
        s = str(value).strip()
        return None if s in ("-", "", "0.0.0.0") else s

    def _normalize_action(self, value: Any) -> str | None:
        """Map WAF action strings to canonical ALLOW/DENY."""
        if not value:
            return None
        v = str(value).upper().strip()
        if any(x in v for x in ("ALLOW", "PERMIT", "PASS", "ACCEPT")):
            return "ALLOW"
        if any(x in v for x in ("DENY", "DROP", "BLOCK", "REJECT")):
            return "DENY"
        return str(value).strip()

    def _extract_uri_parts(self, raw_uri: Any) -> tuple[str | None, str | None]:
        """Split URL/URI into path and query fields."""
        if not raw_uri:
            return None, None

        uri = str(raw_uri).strip()
        if not uri:
            return None, None

        if "?" not in uri and "=" in uri and not uri.startswith("/") and "://" not in uri:
            return None, uri

        parsed = urlsplit(uri)
        path = parsed.path or None
        query = parsed.query or None

        if not path and "?" in uri:
            path = uri.split("?", 1)[0] or None

        if not path and uri.startswith("/"):
            path = uri

        return path, query

    def _parse_timestamp(self, data: dict[str, Any]) -> datetime | None:
        """Try WAF-specific timestamp formats."""
        ts_val = self.find_column(data, "timestamp")
        if not ts_val:
            return None

        ts_str = str(ts_val).strip()

        formats = [
            # "18 Aug 2025, 10:21 PM"
            "%d %b %Y, %I:%M %p",
            # Standard ISO variants
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            # Apache-style inside the column
            "%d/%b/%Y:%H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        # Unix epoch fallback
        try:
            ts_float = float(ts_str)
            if ts_float > 1e12:
                ts_float /= 1000
            return datetime.fromtimestamp(ts_float)
        except (ValueError, OSError):
            pass

        logger.warning(f"Could not parse WAF timestamp | value={ts_str}")
        return None

    def _parse_port(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            port = int(float(str(value)))
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    def _parse_int(self, value: Any) -> int | None:
        if value is None or str(value).strip() in ("-", ""):
            return None
        try:
            return int(float(str(value)))
        except (ValueError, TypeError):
            return None


# Module-level set aliases used in can_parse (defined after class for readability)
_REQUIRED_INDICATORS = WebWAFParser._REQUIRED_INDICATORS
_BONUS_INDICATORS = WebWAFParser._BONUS_INDICATORS
