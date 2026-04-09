"""
Normalization Service

Transforms parsed events into the normalized internal schema.
Ensures consistent data format across all log sources.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from core.config import get_settings
from core.logging import get_logger
from shared_models.events import (
    EventAction,
    EventBatch,
    NetworkProtocol,
    NormalizedEvent,
    ParsedEvent,
)

logger = get_logger(__name__)


class NormalizationService:
    """
    Service for normalizing parsed events into internal schema.

    Responsibilities:
    - Map vendor-specific fields to canonical schema
    - Validate and clean data
    - Assign stable event IDs
    - Classify internal vs external IPs
    """

    # RFC 1918 private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ]

    # Action normalization mapping
    ACTION_MAP = {
        # Allow variants
        "ALLOW": EventAction.ALLOW,
        "PERMIT": EventAction.ALLOW,
        "ACCEPT": EventAction.ALLOW,
        "PASS": EventAction.ALLOW,
        "SUCCESS": EventAction.ALLOW,
        "OK": EventAction.ALLOW,
        # Deny variants
        "DENY": EventAction.DENY,
        "DROP": EventAction.DENY,
        "BLOCK": EventAction.DENY,
        "REJECT": EventAction.DENY,
        "DISCARD": EventAction.DENY,
        "FAIL": EventAction.DENY,
        "FAILURE": EventAction.DENY,
        "FAILED": EventAction.DENY,
    }

    # Protocol normalization mapping
    PROTOCOL_MAP = {
        "TCP": NetworkProtocol.TCP,
        "6": NetworkProtocol.TCP,
        "UDP": NetworkProtocol.UDP,
        "17": NetworkProtocol.UDP,
        "ICMP": NetworkProtocol.ICMP,
        "1": NetworkProtocol.ICMP,
        "HTTP": NetworkProtocol.HTTP,
        "HTTPS": NetworkProtocol.HTTPS,
        "DNS": NetworkProtocol.DNS,
        "SSH": NetworkProtocol.SSH,
        "RDP": NetworkProtocol.RDP,
    }

    def __init__(self):
        self.settings = get_settings()
        self.events_normalized = 0
        self.normalization_errors = 0

    def normalize_event(self, parsed: ParsedEvent) -> NormalizedEvent | None:
        """
        Normalize a single parsed event.

        Args:
            parsed: Parsed event from CSV

        Returns:
            Normalized event or None if normalization fails
        """
        try:
            # Extract and validate IPs (require at least one)
            src_ip = self._normalize_ip(parsed.source_address)
            dst_ip = self._normalize_ip(parsed.destination_address)
            
            # Reject only if BOTH IPs are missing (false positive)
            if not src_ip and not dst_ip:
                logger.warning(
                    f"Missing both source and destination IPs | file_id={parsed.file_id}, row_hash={parsed.row_hash}"
                )
                self.normalization_errors += 1
                return None
            
            # If dst_ip is available, prioritize it as the source (per requirement)
            if dst_ip:
                src_ip = dst_ip
                dst_ip = None
            
            # Ensure src_ip and dst_ip are never the same
            if src_ip and dst_ip and src_ip == dst_ip:
                logger.warning(
                    f"Source and destination IPs are identical, clearing dst_ip | file_id={parsed.file_id}, ip={src_ip}"
                )
                dst_ip = None

            # Get or infer timestamp - always normalize to naive UTC
            timestamp = self._strip_tz(parsed.timestamp) or datetime.utcnow()

            # Normalize action
            action = self._normalize_action(parsed.action)

            # Normalize protocol
            protocol = self._normalize_protocol(parsed.protocol, parsed.destination_port)

            # Classify internal/external
            is_internal_src = self._is_internal_ip(src_ip)
            is_internal_dst = self._is_internal_ip(dst_ip) if dst_ip else None

            # Extract extended fields from parsed_data if available
            parsed_data = parsed.parsed_data or {}
            vendor_data = parsed.vendor_specific or {}

            raw_uri = (
                parsed_data.get("uri_path")
                or parsed_data.get("url")
                or vendor_data.get("url")
            )
            uri_path, uri_query = self._extract_uri_parts(
                raw_uri,
                parsed_data.get("uri_query"),
            )

            original_message = parsed_data.get("original_message") or parsed.raw_message
            if not original_message and vendor_data:
                original_message = " ".join(
                    f"{k}={v}"
                    for k, v in vendor_data.items()
                    if v is not None and str(v).strip()
                )[:2000]

            # Build normalized event with extended fields
            event = NormalizedEvent(
                event_id=uuid4(),
                file_id=parsed.file_id,
                row_hash=parsed.row_hash,
                timestamp=timestamp,
                src_ip=src_ip,
                src_port=parsed.source_port,
                dst_ip=dst_ip,
                dst_port=parsed.destination_port,
                dst_host=parsed.destination_hostname,
                action=action,
                protocol=protocol,
                username=parsed.username,
                bytes_sent=parsed.bytes_sent,
                bytes_received=parsed.bytes_received,
                duration_ms=parsed.duration_ms,
                application=parsed.application,
                is_internal_src=is_internal_src,
                is_internal_dst=is_internal_dst,
                # Extended fields
                severity=parsed_data.get("severity"),
                session_id=parsed_data.get("session_id"),
                http_method=(str(parsed_data.get("http_method")).upper() if parsed_data.get("http_method") else None),
                http_status=self._safe_int(parsed_data.get("http_status")),
                uri_path=uri_path,
                uri_query=uri_query,
                user_agent=(parsed_data.get("user_agent") or vendor_data.get("user_agent")),
                referrer=(parsed_data.get("referrer") or vendor_data.get("referrer")),
                content_type=(parsed_data.get("content_type") or vendor_data.get("content_type")),
                request_size=self._safe_int(parsed_data.get("request_size")),
                response_size=self._safe_int(parsed_data.get("response_size")),
                process_name=parsed_data.get("process_name"),
                process_id=self._safe_int(parsed_data.get("process_id")),
                command_line=parsed_data.get("command_line"),
                file_name=parsed_data.get("file_name"),
                file_hash=parsed_data.get("file_hash"),
                dns_query=parsed_data.get("dns_query"),
                original_message=original_message,
            )

            self.events_normalized += 1
            return event

        except Exception as e:
            logger.error(
                f"Normalization error | error={e}, file_id={parsed.file_id}, row_hash={parsed.row_hash}"
            )
            self.normalization_errors += 1
            return None

    def normalize_batch(self, parsed_events: list[ParsedEvent]) -> EventBatch:
        """
        Normalize a batch of parsed events.

        Args:
            parsed_events: List of parsed events

        Returns:
            EventBatch with normalized events
        """
        if not parsed_events:
            return EventBatch(
                file_id=uuid4(),
                events=[],
                total_rows_processed=0,
                parse_error_count=0,
            )

        file_id = parsed_events[0].file_id
        normalized = []
        error_count = 0

        for parsed in parsed_events:
            event = self.normalize_event(parsed)
            if event:
                normalized.append(event)
            else:
                error_count += 1

        logger.info(
            f"Batch normalization complete | file_id={file_id}, total={len(parsed_events)}, normalized={len(normalized)}, errors={error_count}"
        )

        return EventBatch(
            file_id=file_id,
            events=normalized,
            total_rows_processed=len(parsed_events),
            parse_error_count=error_count,
        )

    def _extract_uri_parts(
        self,
        raw_uri: Any,
        explicit_query: Any | None = None,
    ) -> tuple[str | None, str | None]:
        """Normalize URI into path + query parts."""
        query = str(explicit_query).strip() if explicit_query else None
        if not raw_uri:
            return None, query

        uri = str(raw_uri).strip()
        if not uri:
            return None, query

        # Handle bare query-string payloads
        if "?" not in uri and "=" in uri and not uri.startswith("/") and "://" not in uri:
            return None, query or uri

        parsed = urlsplit(uri)
        path = parsed.path or None
        parsed_query = parsed.query or None

        if not path and "?" in uri:
            path = uri.split("?", 1)[0] or None
        if not query:
            query = parsed_query

        if not path and uri.startswith("/"):
            path = uri

        return path, query

    def _normalize_ip(self, ip_str: str | None) -> str | None:
        """Normalize and validate IP address. Treats '-' as missing value."""
        if not ip_str:
            return None

        ip_str = str(ip_str).strip()
        
        # Treat "-" as missing value (common placeholder in logs)
        if ip_str == "-":
            return None

        # Remove common prefixes
        for prefix in ["::ffff:", "::FFFF:"]:
            if ip_str.startswith(prefix):
                ip_str = ip_str[len(prefix):]

        try:
            ip = ipaddress.ip_address(ip_str)
            return str(ip)
        except ValueError:
            # Try to extract IP from string
            import re

            ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
            match = re.search(ip_pattern, ip_str)
            if match:
                try:
                    ip = ipaddress.ip_address(match.group())
                    return str(ip)
                except ValueError:
                    pass

        return None

    @staticmethod
    def _strip_tz(dt: datetime | None) -> datetime | None:
        """
        Convert any datetime to a naive UTC datetime.

        If the datetime is already naive (no tzinfo), return it unchanged.
        If it is tz-aware, convert to UTC then strip tzinfo so it is
        consistent with the rest of the pipeline which uses naive UTC
        throughout (datetime.utcnow(), etc.).
        """
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt  # already naive
        return dt.astimezone(timezone.utc).replace(tzinfo=None)

    def _normalize_action(self, action: str | None) -> EventAction:
        """Normalize action to standard enum."""
        if not action:
            return EventAction.UNKNOWN

        action_upper = str(action).upper().strip()
        return self.ACTION_MAP.get(action_upper, EventAction.UNKNOWN)

    def _normalize_protocol(
        self,
        protocol: str | None,
        dst_port: int | None = None,
    ) -> NetworkProtocol:
        """Normalize protocol, inferring from port if needed."""
        if protocol:
            proto_upper = str(protocol).upper().strip()
            if proto_upper in self.PROTOCOL_MAP:
                return self.PROTOCOL_MAP[proto_upper]

        # Infer from port
        if dst_port:
            port_protocol_map = {
                22: NetworkProtocol.SSH,
                80: NetworkProtocol.HTTP,
                443: NetworkProtocol.HTTPS,
                53: NetworkProtocol.DNS,
                3389: NetworkProtocol.RDP,
            }
            if dst_port in port_protocol_map:
                return port_protocol_map[dst_port]

        return NetworkProtocol.OTHER

    def _safe_int(self, value: Any) -> int | None:
        """Safely convert parser values to int."""
        if value is None:
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        try:
            return int(float(text))
        except (ValueError, TypeError):
            return None

    def _is_internal_ip(self, ip_str: str) -> bool:
        """Check if IP is internal (private)."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def get_stats(self) -> dict[str, Any]:
        """Get normalization statistics."""
        total = self.events_normalized + self.normalization_errors
        return {
            "events_normalized": self.events_normalized,
            "normalization_errors": self.normalization_errors,
            "success_rate": (self.events_normalized / total if total > 0 else 0),
        }
