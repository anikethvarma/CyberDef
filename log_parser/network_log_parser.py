"""
Network Log Parser

Parser for general network flow and connection logs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from log_parser.base import BaseParser, ParserRegistry
from shared_models.events import ParsedEvent, RawEventRow
from core.logging import get_logger

logger = get_logger(__name__)


@ParserRegistry.register
class NetworkLogParser(BaseParser):
    """
    Parser for network flow and connection logs.
    
    Supports:
    - NetFlow/IPFIX exports
    - Connection logs
    - DNS logs
    - Proxy logs
    """
    
    name = "network_flow"
    vendor = "multiple"
    description = "Parser for network flow and connection logs"
    
    column_mappings = {
        "timestamp": [
            "timestamp", "time", "start_time", "flow_start",
            "connection_time", "log_time", "datetime",
        ],
        "src_ip": [
            "src_ip", "source_ip", "srcaddr", "sa", "src",
            "client_ip", "origin_ip",
        ],
        "dst_ip": [
            "dst_ip", "dest_ip", "dstaddr", "da", "dst",
            "server_ip", "target_ip", "responder_ip",
        ],
        "src_port": [
            "src_port", "source_port", "sp", "sport",
            "client_port", "origin_port",
        ],
        "dst_port": [
            "dst_port", "dest_port", "dp", "dport",
            "server_port", "target_port", "responder_port",
        ],
        "protocol": [
            "protocol", "proto", "ip_proto", "transport",
        ],
        "bytes": [
            "bytes", "total_bytes", "byte_count", "octets",
        ],
        "packets": [
            "packets", "pkt_count", "packet_count", "pkts",
        ],
        "duration": [
            "duration", "duration_ms", "flow_duration", "connection_duration",
        ],
        "dns_query": [
            "query", "dns_query", "query_name", "qname",
        ],
        "dns_type": [
            "query_type", "dns_type", "qtype", "record_type",
        ],
        "response_code": [
            "rcode", "response_code", "status_code", "http_status",
        ],
        "url": [
            "url", "uri", "request_url", "full_url", "dest_url",
        ],
        "user_agent": [
            "user_agent", "useragent", "ua", "http_user_agent",
        ],
        "method": [
            "method", "http_method", "request_method",
        ],
    }
    
    # Network log indicators
    NETWORK_INDICATORS = [
        "flow", "netflow", "ipfix", "connection", "conn",
        "bytes", "packets", "duration", "dns", "proxy",
    ]
    
    def can_parse(self, columns: list[str], sample_rows: list[dict[str, Any]]) -> float:
        """Detect if this is a network flow log."""
        columns_lower = [c.lower() for c in columns]
        
        # Check for network-specific columns
        indicator_matches = sum(
            1 for indicator in self.NETWORK_INDICATORS
            if any(indicator in col for col in columns_lower)
        )
        
        # Check for IP address columns
        has_ips = any(
            any(ip_name in col for ip_name in ["ip", "addr", "address"])
            for col in columns_lower
        )
        
        # Check for traffic metrics
        has_metrics = any(
            any(metric in col for metric in ["bytes", "packets", "duration"])
            for col in columns_lower
        )
        
        # Calculate confidence
        confidence = 0.0
        if indicator_matches >= 2:
            confidence = 0.6
        elif indicator_matches >= 1:
            confidence = 0.4
        
        if has_ips:
            confidence += 0.15
        if has_metrics:
            confidence += 0.15
        
        return min(confidence, 0.9)
    
    def parse_row(self, raw_row: RawEventRow) -> ParsedEvent:
        """Parse a network flow row."""
        data = raw_row.raw_data
        
        # Parse timestamp
        timestamp = self._parse_timestamp(data)
        
        # Parse network tuple
        src_ip = self._clean_ip(self.find_column(data, "src_ip"))
        dst_ip = self._clean_ip(self.find_column(data, "dst_ip"))
        src_port = self._parse_port(self.find_column(data, "src_port"))
        dst_port = self._parse_port(self.find_column(data, "dst_port"))
        
        # Parse protocol
        protocol = self._normalize_protocol(self.find_column(data, "protocol"))
        
        # Parse traffic metrics
        bytes_total = self._parse_int(self.find_column(data, "bytes"))
        duration = self._parse_int(self.find_column(data, "duration"))
        
        # Build vendor-specific fields
        vendor_fields = {}
        
        # DNS fields
        dns_query = self._clean_value(self.find_column(data, "dns_query"))
        if dns_query:
            vendor_fields["dns_query"] = str(dns_query)
        
        dns_type = self.find_column(data, "dns_type")
        if dns_type:
            vendor_fields["dns_type"] = str(dns_type)
        
        # HTTP/Proxy fields
        url = self.find_column(data, "url")
        if url:
            vendor_fields["url"] = str(url)
        
        method = self.find_column(data, "method")
        if method:
            vendor_fields["method"] = str(method)
        
        user_agent = self.find_column(data, "user_agent")
        if user_agent:
            vendor_fields["user_agent"] = str(user_agent)
        
        response_code = self.find_column(data, "response_code")
        if response_code:
            vendor_fields["response_code"] = str(response_code)
        
        packets = self._parse_int(self.find_column(data, "packets"))
        if packets:
            vendor_fields["packets"] = packets
        
        return ParsedEvent(
            file_id=raw_row.file_id,
            row_hash=raw_row.row_hash,
            timestamp=timestamp,
            source_address=src_ip,
            destination_address=dst_ip,
            destination_hostname=dns_query,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            bytes_sent=bytes_total,  # May need split for bidirectional
            duration_ms=duration,
            vendor_specific=vendor_fields,
        )
    
    def _parse_timestamp(self, data: dict[str, Any]) -> datetime | None:
        """Parse timestamp formats."""
        ts_value = self.find_column(data, "timestamp")
        if not ts_value:
            return None
        
        ts_str = str(ts_value).strip()
        
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
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
    
    def _normalize_protocol(self, value: Any) -> str | None:
        """Normalize protocol."""
        if not value:
            return None
        
        proto = str(value).upper().strip()
        
        proto_map = {
            "6": "TCP",
            "17": "UDP",
            "1": "ICMP",
            "58": "ICMPv6",
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
