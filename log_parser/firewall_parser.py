"""
Firewall Log Parser

Parser for common firewall log formats.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


@ParserRegistry.register
class FirewallLogParser(BaseParser):
    """
    Parser for firewall logs.
    
    Supports common firewall log formats including:
    - Palo Alto
    - Fortinet
    - Cisco ASA
    - Generic firewall CSV exports
    """
    
    name = "firewall"
    vendor = "multiple"
    description = "Parser for common firewall log formats"
    
    # Firewall-specific column mappings
    column_mappings = {
        "timestamp": [
            "timestamp", "receive_time", "generated_time", "log_time",
            "start_time", "eventtime", "date_time",
        ],
        "src_ip": [
            "src", "source", "src_ip", "source_ip", "srcip",
            "src_addr", "nat_src_ip", "xlate_src",
        ],
        "dst_ip": [
            "dst", "dest", "destination", "dst_ip", "dest_ip",
            "dst_addr", "nat_dst_ip", "xlate_dst",
        ],
        "src_port": [
            "sport", "src_port", "source_port", "natsport",
        ],
        "dst_port": [
            "dport", "dst_port", "dest_port", "destination_port", "natdport",
        ],
        "action": [
            "action", "policy_action", "result", "status",
            "fw_action", "rule_action", "disposition",
        ],
        "protocol": [
            "protocol", "proto", "ip_protocol", "app_protocol",
        ],
        "application": [
            "app", "application", "service", "app_name",
        ],
        "rule": [
            "rule", "rule_name", "policy", "policy_name", "acl",
        ],
        "zone_src": [
            "src_zone", "from_zone", "inzone", "source_zone",
        ],
        "zone_dst": [
            "dst_zone", "to_zone", "outzone", "dest_zone",
        ],
        "bytes_sent": [
            "bytes_sent", "sent_bytes", "bytes_out", "outbound_bytes",
        ],
        "bytes_received": [
            "bytes_received", "received_bytes", "bytes_in", "inbound_bytes",
        ],
        "session_id": [
            "session_id", "sessionid", "flow_id", "conn_id",
        ],
        "threat_id": [
            "threat_id", "threat", "signature_id", "sig_id",
        ],
        "url": [
            "url", "uri", "request_url", "dest_url",
        ],
    }
    
    # Firewall-specific keywords to identify this log type
    FIREWALL_INDICATORS = [
        "zone", "policy", "rule", "deny", "allow", "drop",
        "firewall", "fw", "nat", "session",
    ]
    
    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """Detect if this is a firewall log."""
        columns_lower = [c.lower() for c in columns]
        
        # Check for firewall-specific columns
        indicator_matches = sum(
            1 for indicator in self.FIREWALL_INDICATORS
            if any(indicator in col for col in columns_lower)
        )
        
        # Check for action columns with firewall values
        has_firewall_actions = False
        if sample_rows:
            for row in sample_rows[:5]:
                for key, value in row.items():
                    if value and str(value).upper() in ["ALLOW", "DENY", "DROP", "ACCEPT", "REJECT"]:
                        has_firewall_actions = True
                        break
        
        # Check for zone columns
        has_zones = any("zone" in col for col in columns_lower)
        
        # Calculate confidence
        confidence = 0.0
        if indicator_matches >= 3:
            confidence = 0.7
        elif indicator_matches >= 2:
            confidence = 0.5
        elif indicator_matches >= 1:
            confidence = 0.3
        
        if has_firewall_actions:
            confidence += 0.2
        if has_zones:
            confidence += 0.1
        
        return min(confidence, 0.95)
    
    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse a firewall log row."""
        data = raw_row.raw_data
        
        # Parse timestamp
        timestamp = self._parse_timestamp(data)
        
        # Parse network tuple
        src_ip = self._clean_ip(self.find_column(data, "src_ip"))
        dst_ip = self._clean_ip(self.find_column(data, "dst_ip"))
        src_port = self._parse_port(self.find_column(data, "src_port"))
        dst_port = self._parse_port(self.find_column(data, "dst_port"))
        
        # Parse action and protocol
        action = self._normalize_action(self.find_column(data, "action"))
        protocol = self._normalize_protocol(self.find_column(data, "protocol"))
        
        # Parse application
        application = self._clean_value(self.find_column(data, "application"))
        
        # Parse traffic metrics
        bytes_sent = self._parse_int(self.find_column(data, "bytes_sent"))
        bytes_received = self._parse_int(self.find_column(data, "bytes_received"))
        
        # Build vendor-specific fields
        vendor_fields = {}
        
        rule = self.find_column(data, "rule")
        if rule:
            vendor_fields["rule"] = str(rule)
        
        zone_src = self.find_column(data, "zone_src")
        if zone_src:
            vendor_fields["zone_src"] = str(zone_src)
        
        zone_dst = self.find_column(data, "zone_dst")
        if zone_dst:
            vendor_fields["zone_dst"] = str(zone_dst)
        
        session_id = self.find_column(data, "session_id")
        if session_id:
            vendor_fields["session_id"] = str(session_id)
        
        threat_id = self.find_column(data, "threat_id")
        if threat_id:
            vendor_fields["threat_id"] = str(threat_id)
        
        url = self.find_column(data, "url")
        if url:
            vendor_fields["url"] = str(url)
        
        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            action=action,
            protocol=protocol,
            application=application,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            vendor_specific=vendor_fields,
        )
    
    def _parse_timestamp(self, data: dict[str, Any]) -> datetime | None:
        """Parse firewall timestamp formats."""
        ts_value = self.find_column(data, "timestamp")
        if not ts_value:
            return None
        
        ts_str = str(ts_value).strip()
        
        # Firewall-specific formats
        formats = [
            "%Y/%m/%d %H:%M:%S",  # Palo Alto
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%b %d %Y %H:%M:%S",  # Cisco
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        # Unix timestamp
        try:
            ts_float = float(ts_str)
            if ts_float > 1e12:
                ts_float /= 1000
            return datetime.fromtimestamp(ts_float)
        except (ValueError, OSError):
            pass
        
        return None
    
    def _normalize_action(self, value: Any) -> str | None:
        """Normalize firewall action to standard values."""
        if not value:
            return None
        
        action = str(value).upper().strip()
        
        # Map to standard actions
        if action in ["ALLOW", "PERMIT", "ACCEPT", "PASS"]:
            return "ALLOW"
        elif action in ["DENY", "DROP", "BLOCK", "REJECT", "DISCARD"]:
            return "DENY"
        else:
            return action
    
    def _normalize_protocol(self, value: Any) -> str | None:
        """Normalize protocol to standard values."""
        if not value:
            return None
        
        proto = str(value).upper().strip()
        
        # Handle numeric protocols
        proto_map = {
            "6": "TCP",
            "17": "UDP",
            "1": "ICMP",
        }
        
        return proto_map.get(proto, proto)
    
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
