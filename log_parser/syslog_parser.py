"""
Syslog Apache Access Log Parser

Parses log files that contain a single `logevent` column
with embedded syslog-wrapped Apache combined access log entries.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


# Combined regex patterns for new Apache log format
# Pattern 1: Extended format with hostname, daemon, and detailed fields
_APACHE_EXTENDED_RE = re.compile(
    r"<\d+>\w+[\s\d\:]+(?P<HostName>[\S]+)\s(?P<Daemon>[\w\-\d\[\]]+)\:?\s"
    r"(?P<DstIP>[\d\.]+|\-)\s(?P<SrcIP>[\d\.]+|\-)(?:\,\s[\d\.]+\,\s[\d\.]+|\,\s+[\d\.]+|)"
    r"(?:[\s\-]+)(?P<UserID>[\d\-]+)\s+(?:(?P<domain>[a-zA-Z\-\.]+)|(?:\d+\.){3}\d+|).*?"
    r"(?P<SystemTStamp>\d{2}[\/\w\:]+).*?\][\s\"]+(?P<HTTPMethod>\w+)\s(?P<URL>\S+).*?\"?\s"
    r"(?P<responsecode>\d+)\s(?P<RXLen>\d+|\-)\s+(?:(?P<TimeTaken>\d+|-)\s+|)?"
    r"(?:\"?(?P<HTTPReferer>\S+|\-)\"\s\"?(?P<UserAgent>.*)\")?",
    re.DOTALL
)

# Pattern 2: Standard format with hostname and daemon  
_APACHE_STANDARD_RE = re.compile(
    r"<\d+>\w{3}\s+\d{1,2}\s+\d{2}\:\d{2}\:\d{2}\s+(?P<HostName>[\S]+)\s(?P<Daemon>[\w\-\d\[\]]+)\:\s"
    r"(?P<DstIP>[\d\.\:]+|\-)\s(?P<SrcIP>[\d\.]+|\-)(?:\,\s[\d\.]+|\s\,\:|\s\,\S|\:\S+|\s\,[\d\.]+|\,[\d\.]+|\s\,\s[\d\.:]+|(?:\d+\.)+\S*\s|[,%\d]|\s)*\s"
    r"(?:(?P<domain>\S+|\-)\s)?(?P<UserID>\d+|\-)\s[^a-zA-z]*?\[(?P<SystemTStamp>\d{2}\S+).*?\][\s\"]+(?P<HTTPMethod>\w+)\s(?P<URL>\S+).*?\s"
    r"(?P<responsecode>\d+)\s(?P<RXLen>\d+|\-)(?:\s(?P<TimeTaken>\d+))?\s+"
    r"(\"(?P<HTTPReferer>\S+|)\"\s\"?(?P<UserAgent>\-|.*)\")?",
    re.DOTALL
)

# Pattern 3: Flexible pattern for simpler formats
_APACHE_FLEXIBLE_RE = re.compile(
    r"<\d+>\w+\s+\d{1,2}\s+\d{2}\:\d{2}\:\d{2}\s+(?P<HostName>[\S]+)\s(?P<Daemon>[\w\-\d\[\]]+)\:?\s"
    r"(?P<DstIP>[\d\.]+|\-)\s(?P<SrcIP>[\d\.]+|\-)\s+"
    r"(?P<UserID>[\w\-]+)\s+(?P<domain>[\w\-\.]+)\s+"
    r"(?P<SystemTStamp>\d{2}[\/\w\:]+).*?\]\s*\"?(?P<HTTPMethod>\w+)\s(?P<URL>\S+).*?\"\s+"
    r"(?P<responsecode>\d+)\s(?P<RXLen>\d+|\-)(?:\s(?P<TimeTaken>\d+))?"
    r"(?:\s+\"?(?P<HTTPReferer>\S+|\-)\"\s\"?(?P<UserAgent>.*)\")?",
    re.DOTALL
)

# Legacy fallback patterns for backward compatibility
_LEGACY_SYSLOG_PREFIX_RE = re.compile(
    r"^<\d+>\s*\w+\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+:\s+"
)

_LEGACY_REQUEST_RE = re.compile(
    r'"(?P<method>[A-Z]+)\s+(?P<uri>.+?)(?:\s+HTTP/[^\"]*)?"'
)
_LEGACY_TIMESTAMP_RE = re.compile(r"\[(?P<ts>[^\]]+)\]")
_LEGACY_STATUS_PREFIX_RE = re.compile(
    r"^(?P<status>\d{3})(?:\s+(?P<bytes>\S+))?(?:\s+(?P<timetaken>\S+))?"
)

_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Column names the file may use for the raw log event
_LOGEVENT_COLS = {"logevent", "log_event", "raw_log", "raw_event", "event"}


@ParserRegistry.register
class SyslogApacheParser(BaseParser):
    """
    Parser for files with a single syslog-wrapped Apache access log column.

    Detects files where every row is a syslog-prefixed Apache Combined Log
    Format string stored in a single CSV column. Extracts source/destination
    IPs, HTTP method, URI, status code, response size and user-agent.
    """

    name = "syslog_apache"
    vendor = "apache_httpd"
    description = "Parser for syslog-wrapped Apache combined access log in a single column"

    column_mappings: dict[str, list[str]] = {}

    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """
        Return high confidence when:
        1. There is effectively one non-empty column.
        2. Sample rows match new syslog format patterns.
        """
        if not columns:
            return 0.0

        non_empty_cols = [c.strip() for c in columns if c.strip()]
        if len(non_empty_cols) > 2:
            return 0.0

        col_match = any(c.lower() in _LOGEVENT_COLS for c in non_empty_cols)
        if not col_match and len(non_empty_cols) != 1:
            return 0.0

        pattern_hits = 0
        for row in sample_rows[:10]:
            raw = self._get_raw(row)
            if raw:
                # Check for new patterns first
                if (_APACHE_EXTENDED_RE.match(raw) or 
                    _APACHE_STANDARD_RE.match(raw) or 
                    _APACHE_FLEXIBLE_RE.match(raw) or
                    _LEGACY_SYSLOG_PREFIX_RE.match(raw)):
                    pattern_hits += 1

        if pattern_hits == 0:
            return 0.0

        ratio = pattern_hits / min(len(sample_rows), 10)
        return 0.6 + (ratio * 0.35)  # Higher confidence for new patterns

    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse a syslog-wrapped Apache access log row with new regex patterns."""
        raw = self._get_raw(raw_row.raw_data) or ""

        # Try new extended pattern first
        extended_match = _APACHE_EXTENDED_RE.match(raw)
        if extended_match:
            return self._build_from_extended(raw_row, raw, extended_match)

        # Try new standard pattern
        standard_match = _APACHE_STANDARD_RE.match(raw)
        if standard_match:
            return self._build_from_standard(raw_row, raw, standard_match)

        # Try flexible pattern
        flexible_match = _APACHE_FLEXIBLE_RE.match(raw)
        if flexible_match:
            return self._build_from_flexible(raw_row, raw, flexible_match)

        # Fallback to legacy parsing for backward compatibility
        body = _LEGACY_SYSLOG_PREFIX_RE.sub("", raw).strip()
        body = body.replace("--[", "- - [")

        # Legacy flexible fallback
        parsed = self._parse_flexible_legacy(body)
        if not parsed:
            logger.debug(f"Could not parse syslog/apache line | row_hash={raw_row.row_hash}")
            return ParsedEvent(
                file_id=raw_row.file_id,
                row_hash=raw_row.row_hash,
            )

        status_int = self._parse_int(parsed.get("status"))

        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=self._parse_ts(parsed.get("ts")),
            source_address=self._clean_ip(parsed.get("src_ip")),
            destination_address=self._clean_ip(parsed.get("dst_ip")),
            destination_hostname=parsed.get("vhost"),
            destination_port=self._parse_port(parsed.get("port")),
            protocol="HTTP",
            action=("ALLOW" if status_int and status_int < 400 else ("DENY" if status_int and status_int >= 400 else None)),
            bytes_sent=self._parse_int(parsed.get("bytes")),
            duration_ms=self._parse_int(parsed.get("timetaken")),
            raw_message=raw[:512],
            parsed_data={
                "http_method": parsed.get("method"),
                "http_status": status_int,
                "uri_path": parsed.get("uri"),
                "user_agent": parsed.get("ua"),
                "referrer": parsed.get("referer"),
                "original_message": raw,
            },
            vendor_specific={"vhost": parsed.get("vhost")},
        )

    def _build_from_extended(self, raw_row: RawEventRow, raw: str, m: re.Match[str]) -> ParsedEvent:
        """Build ParsedEvent from extended regex match."""
        src_ip = self._clean_ip(m.group("SrcIP"))
        dst_ip = self._clean_ip(m.group("DstIP"))
        
        # If the log only contains one IP in the DstIP slot (e.g. 0.0.0.0 - - -), it is the client/source IP
        if not src_ip and dst_ip:
            src_ip, dst_ip = dst_ip, None

        timestamp = self._parse_ts(m.group("SystemTStamp"))
        status = self._parse_int(m.group("responsecode"))
        bytes_sent = self._parse_int(m.group("RXLen"))
        timetaken = self._parse_int(m.group("TimeTaken"))
        hostname = m.group("HostName")
        daemon = m.group("Daemon")
        user_id = m.group("UserID")
        domain = m.group("domain")

        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=hostname,
            destination_port=None,  # Not captured in this pattern
            protocol="HTTP",
            action="ALLOW" if status and status < 400 else ("DENY" if status and status >= 400 else None),
            bytes_sent=bytes_sent,
            duration_ms=timetaken,
            raw_message=raw[:512],
            parsed_data={
                "http_method": m.group("HTTPMethod"),
                "http_status": status,
                "uri_path": m.group("URL"),
                "user_agent": m.group("UserAgent"),
                "referrer": m.group("HTTPReferer"),
                "original_message": raw,
                "user_id": user_id,
                "domain": domain,
                "daemon": daemon,
            },
            vendor_specific={
                "hostname": hostname,
                "daemon": daemon,
                "user_id": user_id,
                "domain": domain,
            },
        )

    def _build_from_standard(self, raw_row: RawEventRow, raw: str, m: re.Match[str]) -> ParsedEvent:
        """Build ParsedEvent from standard regex match."""
        src_ip = self._clean_ip(m.group("SrcIP"))
        dst_ip = self._clean_ip(m.group("DstIP"))
        
        # If the log only contains one IP in the DstIP slot (e.g. 0.0.0.0 - - -), it is the client/source IP
        if not src_ip and dst_ip:
            src_ip, dst_ip = dst_ip, None

        timestamp = self._parse_ts(m.group("SystemTStamp"))
        status = self._parse_int(m.group("responsecode"))
        bytes_sent = self._parse_int(m.group("RXLen"))
        timetaken = self._parse_int(m.group("TimeTaken"))
        hostname = m.group("HostName")
        daemon = m.group("Daemon")
        user_id = m.group("UserID")
        domain = m.group("domain")

        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=hostname,
            destination_port=None,  # Not captured in this pattern
            protocol="HTTP",
            action="ALLOW" if status and status < 400 else ("DENY" if status and status >= 400 else None),
            bytes_sent=bytes_sent,
            duration_ms=timetaken,
            raw_message=raw[:512],
            parsed_data={
                "http_method": m.group("HTTPMethod"),
                "http_status": status,
                "uri_path": m.group("URL"),
                "user_agent": m.group("UserAgent"),
                "referrer": m.group("HTTPReferer"),
                "original_message": raw,
                "user_id": user_id,
                "domain": domain,
                "daemon": daemon,
            },
            vendor_specific={
                "hostname": hostname,
                "daemon": daemon,
                "user_id": user_id,
                "domain": domain,
            },
        )

    def _build_from_flexible(self, raw_row: RawEventRow, raw: str, m: re.Match[str]) -> ParsedEvent:
        """Build ParsedEvent from flexible regex match."""
        src_ip = self._clean_ip(m.group("SrcIP"))
        dst_ip = self._clean_ip(m.group("DstIP"))
        
        # If the log only contains one IP in the DstIP slot (e.g. 0.0.0.0 - - -), it is the client/source IP
        if not src_ip and dst_ip:
            src_ip, dst_ip = dst_ip, None

        timestamp = self._parse_ts(m.group("SystemTStamp"))
        status = self._parse_int(m.group("responsecode"))
        bytes_sent = self._parse_int(m.group("RXLen"))
        timetaken = self._parse_int(m.group("TimeTaken"))
        hostname = m.group("HostName")
        daemon = m.group("Daemon")
        user_id = m.group("UserID")
        domain = m.group("domain")

        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=hostname,
            destination_port=None,
            protocol="HTTP",
            action="ALLOW" if status and status < 400 else ("DENY" if status and status >= 400 else None),
            bytes_sent=bytes_sent,
            duration_ms=timetaken,
            raw_message=raw[:512],
            parsed_data={
                "http_method": m.group("HTTPMethod"),
                "http_status": status,
                "uri_path": m.group("URL"),
                "user_agent": m.group("UserAgent"),
                "referrer": m.group("HTTPReferer"),
                "original_message": raw,
                "user_id": user_id,
                "domain": domain,
                "daemon": daemon,
            },
            vendor_specific={
                "hostname": hostname,
                "daemon": daemon,
                "user_id": user_id,
                "domain": domain,
            },
        )

    def _parse_flexible_legacy(self, body: str) -> dict[str, Any] | None:
        """Parse apache-like lines with irregular spacing/token layout (legacy)."""
        req = _LEGACY_REQUEST_RE.search(body)
        if not req:
            return None

        prefix = body[:req.start()].strip()
        suffix = body[req.end():].strip()

        ts_match = _LEGACY_TIMESTAMP_RE.search(prefix)
        ts = ts_match.group("ts") if ts_match else None

        if ts_match:
            left = prefix[:ts_match.start()].strip()
        else:
            left = prefix

        tokens = left.split()
        if len(tokens) < 2:
            return None

        src_ip = tokens[0]
        dst_ip = tokens[1]
        port = tokens[2] if len(tokens) > 2 else None
        vhost = tokens[3] if len(tokens) > 3 and tokens[3] != "-" else None

        status = None
        bytes_sent = None
        timetaken = None
        status_match = _LEGACY_STATUS_PREFIX_RE.match(suffix)
        if status_match:
            status = status_match.group("status")
            bytes_sent = status_match.group("bytes")
            timetaken = status_match.group("timetaken")

        quoted = re.findall(r'"([^"]*)"', suffix)
        referer = quoted[0] if len(quoted) >= 1 else None
        ua = quoted[1] if len(quoted) >= 2 else None

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "vhost": vhost,
            "ts": ts,
            "method": req.group("method"),
            "uri": req.group("uri"),
            "status": status,
            "bytes": bytes_sent,
            "timetaken": timetaken,
            "referer": referer,
            "ua": ua,
        }

    def _get_raw(self, data: dict[str, Any]) -> str | None:
        """Pull the raw log string from whatever column it lives in."""
        for key in data:
            if key.strip().lower() in _LOGEVENT_COLS:
                return str(data[key]).strip() if data[key] else None
        for val in data.values():
            if val:
                return str(val).strip()
        return None

    def _clean_ip(self, value: Any) -> str | None:
        """Return IP string or None for dash/empty placeholders."""
        if value is None:
            return None
        s = str(value).strip()
        if s in ("-", ""):
            return None
        return s

    def _parse_ts(self, ts_str: str | None) -> datetime | None:
        """Parse Apache timestamp into naive UTC datetime."""
        if not ts_str:
            return None

        cleaned = re.sub(r"\s+", " ", ts_str.strip())
        # Handle exported timezone without sign: "... 0530" -> "... +0530"
        if re.search(r"\s\d{4}$", cleaned):
            cleaned = cleaned[:-5] + " +" + cleaned[-4:]

        try:
            dt = datetime.strptime(cleaned, _TS_FORMAT)
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return None

    def _parse_port(self, value: Any) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        try:
            port = int(text)
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    def _parse_int(self, value: Any) -> int | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        try:
            return int(text)
        except (ValueError, TypeError):
            return None


