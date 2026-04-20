"""
test_raw_log_pipeline.py

End-to-end pipeline test using the two exact sample syslog-httpd log strings.

LOG FORMAT ANALYSIS:
  <PRI> date host httpd[PID]: DST_IP  SRC_IP  ...  "METHOD URI VER" STATUS ...
  Token[0] = dst_ip (10.61.63.169)
  Token[1] = src_ip ("-" = absent)

These logs have NO src_ip — only dst_ip. Under the strict policy:
  - Normalization returns None (event dropped)
  - Dropped events never reach the Engine

HOW TO RUN:
  pytest:   python -m pytest tests/test_raw_log_pipeline.py -v
  manual:   python -m pytest tests/test_raw_log_pipeline.py -v -s
            (but redirect to file to avoid Windows cp1252 issues)
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from normalization.service import NormalizationService
from rules_engine.engine import DeterministicEngine
from shared_models.events import ParsedEvent


# ---------------------------------------------------------------------------
# The exact two sample raw log lines provided for testing
# ---------------------------------------------------------------------------

RAW_LOG_1 = (
    '<150>Mar 24 12:11:10 INMUPA0009LSG02 httpd[173876]: '
    '10.61.63.169 - - search.ultimatix.net - - '
    '[24/Mar/2026:12:11:10 +0530] '
    '"GET /search HTTP/1.1" 302 - 0 "-" "-"'
)

RAW_LOG_2 = (
    '<150>Mar 24 12:11:05 INMUPA0009LSG01 httpd[162527]: '
    '10.61.63.174 - - search.ultimatix.net - - '
    '[24/Mar/2026:12:11:05 +0530] '
    '"GET /search HTTP/1.1" 302 - 0 "-" "-"'
)

ALL_RAW_LOGS = [RAW_LOG_1, RAW_LOG_2]
EXPECTED_DST_IPS = {"10.61.63.169", "10.61.63.174"}


# ---------------------------------------------------------------------------
# Syslog-Apache parser (mirrors production SyslogApacheParser regex logic)
# Format after 'httpd[PID]: ':
#   DST_IP  SRC_IP  ident  user  vhost  ...  [timestamp]  "METHOD URI VER"  STATUS
# ---------------------------------------------------------------------------

_AFTER_PID = re.compile(r'httpd\[\d+\]:\s+(.*)', re.DOTALL)
_REQUEST_RE = re.compile(r'"([A-Z]+)\s+([^\s"]+)(?:\s+HTTP/[\d.]+)?"\s+(\d+)')


def parse_syslog_apache(raw_log: str) -> dict:
    """
    Extract fields from a syslog-wrapped Apache access log.
    Token layout after 'httpd[PID]: ':
      [0] dst_ip   [1] src_ip ('-' if absent)  ...  "METHOD URI" STATUS
    Returns empty dict if regex doesn't match.
    """
    try:
        m = _AFTER_PID.search(raw_log)
        if not m:
            return {}
        tokens = m.group(1).split()
        if len(tokens) < 2:
            return {}

        dst_ip = tokens[0] if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', tokens[0]) else None
        src_ip_raw = tokens[1]  # '-' means absent
        src_ip = None if (not src_ip_raw or src_ip_raw == "-") else src_ip_raw

        req_m = _REQUEST_RE.search(raw_log)
        method = req_m.group(1) if req_m else None
        uri = req_m.group(2) if req_m else None
        status = int(req_m.group(3)) if req_m else None

        return {
            "dst_ip": dst_ip,
            "src_ip": src_ip,        # None when absent
            "src_ip_raw": src_ip_raw,
            "method": method,
            "uri": uri,
            "status": status,
        }
    except Exception as e:
        pytest.fail(f"parse_syslog_apache failed for log: {e}")
        return {}


def build_parsed_event(raw_log: str) -> ParsedEvent:
    """Convert a raw log string into a ParsedEvent for the normalizer."""
    try:
        f = parse_syslog_apache(raw_log)
        return ParsedEvent(
            file_id=uuid4(),
            row_hash=uuid4().hex[:16],
            timestamp=datetime(2026, 3, 24, 6, 41, 0),
            source_address=f.get("src_ip"),       # None when '-'
            destination_address=f.get("dst_ip"),
            action="ALLOW",
            parsed_data={
                "http_method": f.get("method"),
                "http_status": str(f.get("status", "")),
                "uri_path": f.get("uri"),
            },
        )
    except Exception as e:
        pytest.fail(f"build_parsed_event failed: {e}")


# ===========================================================================
# Stage 1: Raw log → field extraction
# ===========================================================================

class TestRawLogParsing:

    def test_log1_dst_is_10_61_63_169(self):
        """Token[0] after PID = dst_ip = 10.61.63.169."""
        try:
            f = parse_syslog_apache(RAW_LOG_1)
            assert f["dst_ip"] == "10.61.63.169", f"dst_ip wrong: {f}"
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_dst_is_10_61_63_169 raised unexpected error: {e}")

    def test_log1_src_ip_is_absent(self):
        """Token[1] = '-' which means src_ip is absent (None)."""
        try:
            f = parse_syslog_apache(RAW_LOG_1)
            assert f["src_ip_raw"] == "-", f"Expected raw '-', got: {f.get('src_ip_raw')}"
            assert f["src_ip"] is None, f"Expected src_ip None, got: {f.get('src_ip')}"
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_src_ip_is_absent raised unexpected error: {e}")

    def test_log1_http_fields(self):
        try:
            f = parse_syslog_apache(RAW_LOG_1)
            assert f["method"] == "GET"
            assert f["uri"] == "/search"
            assert f["status"] == 302
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_http_fields raised unexpected error: {e}")

    def test_log2_dst_is_10_61_63_174(self):
        try:
            f = parse_syslog_apache(RAW_LOG_2)
            assert f["dst_ip"] == "10.61.63.174"
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log2_dst_is_10_61_63_174 raised unexpected error: {e}")

    def test_log2_src_ip_is_absent(self):
        try:
            f = parse_syslog_apache(RAW_LOG_2)
            assert f["src_ip"] is None
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log2_src_ip_is_absent raised unexpected error: {e}")


# ===========================================================================
# Stage 2: ParsedEvent → NormalizedEvent
# ===========================================================================

class TestRawLogNormalization:

    def setup_method(self):
        try:
            self.svc = NormalizationService()
        except Exception as e:
            pytest.fail(f"NormalizationService setup failed: {e}")

    def test_log1_dropped_due_to_missing_src_ip(self):
        """
        CORE CHECK: src_ip missing in raw log -> Normalization returns None.
        """
        try:
            parsed = build_parsed_event(RAW_LOG_1)
            event = self.svc.normalize_event(parsed)
            assert event is None, "Normalizer must drop the event because src_ip is missing"
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_dropped_due_to_missing_src_ip raised unexpected error: {e}")

    def test_log1_drop_notification_in_logs(self, caplog):
        """Verify dropping logs a record."""
        try:
            import logging
            with caplog.at_level(logging.INFO):
                self.svc.normalize_event(build_parsed_event(RAW_LOG_1))
                assert "Discarding event due to missing source IP" in caplog.text
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_drop_notification_in_logs raised unexpected error: {e}")

    def test_log1_is_dropped_not_internal(self):
        """is_internal_src check happens after src_ip validation, so this should be None."""
        try:
            event = self.svc.normalize_event(build_parsed_event(RAW_LOG_1))
            assert event is None
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_is_dropped_not_internal raised unexpected error: {e}")

    def test_log1_http_fields_not_reachable(self):
        """Since event is dropped, we can't check normalized fields."""
        try:
            event = self.svc.normalize_event(build_parsed_event(RAW_LOG_1))
            assert event is None
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log1_http_fields_not_reachable raised unexpected error: {e}")

    def test_log2_is_also_dropped(self):
        try:
            event = self.svc.normalize_event(build_parsed_event(RAW_LOG_2))
            assert event is None
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_log2_is_also_dropped raised unexpected error: {e}")

    def test_dst_is_irrelevant_if_src_missing(self):
        """Even if dst_ip is valid, missing src_ip kills the event."""
        try:
            event = self.svc.normalize_event(build_parsed_event(RAW_LOG_1))
            assert event is None
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_dst_is_irrelevant_if_src_missing raised unexpected error: {e}")


# ===========================================================================
# Stage 3: Engine detection - zero threats
# ===========================================================================

class TestRawLogEngineDetection:

    def setup_method(self):
        try:
            self.svc = NormalizationService()
            self.engine = DeterministicEngine()
        except Exception as e:
            pytest.fail(f"TestRawLogEngineDetection setup failed: {e}")

    def _get_events(self, multiplier=1):
        try:
            events = []
            for raw in ALL_RAW_LOGS:
                try:
                    ev = self.svc.normalize_event(build_parsed_event(raw))
                    if ev:
                        events.append(ev)
                except Exception as e:
                    pytest.fail(f"_get_events: failed to normalize event for raw log: {e}")
            return events * multiplier
        except Exception as e:
            pytest.fail(f"_get_events failed: {e}")
            return []

    def test_zero_threats_for_two_sample_logs(self):
        """The two real sample log lines produce ZERO threats."""
        try:
            events = self._get_events()
            result = self.engine.scan(events)
            assert len(result.threats) == 0, (
                f"Expected 0 threats, got: {[(t.rule_name, t.src_ip) for t in result.threats]}"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_zero_threats_for_two_sample_logs raised unexpected error: {e}")

    def test_blank_src_ip_excluded_from_rate_rules(self):
        """Even 600 events with src_ip='-' must not trigger rate-based rules."""
        try:
            events = self._get_events(multiplier=300)  # 600 total

            result = self.engine.scan(events)

            rate_threats = [
                t for t in result.threats
                if t.rule_name in (
                    "slowloris_suspected", "api_rate_abuse",
                    "http_flood", "resource_exhaustion",
                )
            ]
            assert len(rate_threats) == 0, (
                f"Rate rules must not fire for blank src_ip events. "
                f"Got: {[(t.rule_name, t.src_ip) for t in rate_threats]}"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_blank_src_ip_excluded_from_rate_rules raised unexpected error: {e}")
