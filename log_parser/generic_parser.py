"""
Generic CSV Parser

Fallback parser for CSV files without specific format detection.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


@ParserRegistry.register
class GenericCSVParser(BaseParser):
    """
    Generic CSV parser that attempts to extract common fields.
    
    Used as a fallback when no specific parser matches.
    """
    
    name = "generic"
    vendor = "generic"
    description = "Generic CSV parser with auto-detection of common fields"
    
    # Common column name variations
    column_mappings = {
        "timestamp": [
            "timestamp", "time", "datetime", "date_time", "event_time",
            "log_time", "created_at", "occurred_at", "@timestamp",
            "eventtime", "start_time", "end_time",
        ],
        "src_ip": [
            "src_ip", "source_ip", "srcip", "src", "source", "source_address",
            "src_addr", "sourceip", "client_ip", "clientip", "from_ip",
        ],
        "dst_ip": [
            "dst_ip", "dest_ip", "destination_ip", "dstip", "dst", "dest",
            "destination", "destination_address", "dst_addr", "destip",
            "server_ip", "serverip", "to_ip", "target_ip",
        ],
        "dst_host": [
            "dst_host", "dest_host", "destination_host", "hostname",
            "server_name", "servername", "target_host", "host",
            "destination_hostname", "dest_hostname",
        ],
        "src_port": [
            "src_port", "source_port", "srcport", "sport",
            "client_port", "clientport",
        ],
        "dst_port": [
            "dst_port", "dest_port", "destination_port", "dstport", "dport",
            "port", "server_port", "serverport", "target_port",
        ],
        "action": [
            "action", "event_action", "status", "result", "outcome",
            "disposition", "policy_action", "rule_action", "verdict",
        ],
        "protocol": [
            "protocol", "proto", "ip_protocol", "network_protocol",
            "transport_protocol", "l4_protocol",
        ],
        "username": [
            "username", "user", "user_name", "account", "account_name",
            "login", "user_id", "userid", "principal",
        ],
        "application": [
            "application", "app", "app_name", "service", "service_name",
            "process", "program",
        ],
        "bytes_sent": [
            "bytes_sent", "sent_bytes", "bytes_out", "outbound_bytes",
            "tx_bytes", "upload_bytes",
        ],
        "bytes_received": [
            "bytes_received", "received_bytes", "bytes_in", "inbound_bytes",
            "rx_bytes", "download_bytes",
        ],
        "message": [
            "message", "msg", "log_message", "description", "details",
            "event_message", "raw_message",
        ],
    }
    
    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """
        Generic parser always returns low confidence as fallback.
        """
        # Check for any recognizable columns
        columns_lower = [c.lower() for c in columns]
        
        matched = 0
        for field, variations in self.column_mappings.items():
            for var in variations:
                if var.lower() in columns_lower:
                    matched += 1
                    break
        
        # Return low base confidence with bonus for matched columns
        return 0.1 + (matched * 0.05)
    
    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse a row using generic field detection."""
        data = raw_row.raw_data
        
        # Extract timestamp
        timestamp = self._parse_timestamp(data)
        
        # Extract network fields
        src_ip = self._clean_ip(self.find_column(data, "src_ip"))
        dst_ip = self._clean_ip(self.find_column(data, "dst_ip"))
        dst_host = self._clean_value(self.find_column(data, "dst_host"))
        src_port = self._parse_port(self.find_column(data, "src_port"))
        dst_port = self._parse_port(self.find_column(data, "dst_port"))
        
        # Extract action and protocol
        action = self._clean_value(self.find_column(data, "action"))
        protocol = self._clean_value(self.find_column(data, "protocol"))
        
        # Extract identity
        username = self._clean_value(self.find_column(data, "username"))
        
        # Extract traffic data
        bytes_sent = self._parse_int(self.find_column(data, "bytes_sent"))
        bytes_received = self._parse_int(self.find_column(data, "bytes_received"))
        
        # Extract message
        message = self._clean_value(self.find_column(data, "message"))
        
        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=dst_host,
            source_port=src_port,
            destination_port=dst_port,
            action=action,
            protocol=protocol,
            username=username,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            raw_message=message,
            vendor_specific={
                k: v for k, v in data.items()
                if v is not None and str(v).strip()
            },
        )
    
    def _parse_timestamp(self, data: dict[str, Any]) -> datetime | None:
        """Attempt to parse timestamp from various formats."""
        ts_value = self.find_column(data, "timestamp")
        if not ts_value:
            return None
        
        ts_str = str(ts_value).strip()
        
        # Common timestamp formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%b %d %Y %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        # Try Unix timestamp
        try:
            ts_float = float(ts_str)
            if ts_float > 1e12:  # Milliseconds
                ts_float /= 1000
            return datetime.fromtimestamp(ts_float)
        except (ValueError, OSError):
            pass
        
        logger.warning(f"Could not parse timestamp: {ts_str}")
        return None
    
    def _parse_port(self, value: Any) -> int | None:
        """Parse port number."""
        if value is None:
            return None
        try:
            port = int(float(str(value)))
            if 0 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        return None
    
    def _parse_int(self, value: Any) -> int | None:
        """Parse integer value."""
        if value is None:
            return None
        try:
            return int(float(str(value)))
        except (ValueError, TypeError):
            return None
