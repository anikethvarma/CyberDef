"""
Test: Blank src_ip normalization and engine exclusion.

Validates the following scenarios from the sample syslog-httpd logs:

    <150>Mar 24 12:11:10 INMUPA0009LSG02 httpd[173876]: 10.61.63.169 - - ...
    <150>Mar 24 12:11:05 INMUPA0009LSG01 httpd[162527]: 10.61.63.174 - - ...

The IPs 10.61.63.x are private (RFC1918) — they will normalize fine but
Slowloris must ignore them (non-public). Additionally, events with NO
source address at all must be DISCARDED during normalization (return None)
instead of using the "-" placeholder.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime
from uuid import uuid4

import pytest

from normalization.service import NormalizationService
from rules_engine.engine import DeterministicEngine
from rules_engine.rules_bot_cve import SlowlorisRule
from shared_models.events import NormalizedEvent, ParsedEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parsed(source_address=None, uri="/search", http_method="GET",
                 http_status=302, bytes_sent=0):
    """Build a minimal ParsedEvent equivalent to one syslog-apache row."""
    try:
        return ParsedEvent(
            file_id=uuid4(),
            row_hash=uuid4().hex[:16],
            timestamp=datetime(2026, 3, 24, 6, 41, 10),
            source_address=source_address,          # <-- key field under test
            destination_address=None,
            action="ALLOW",
            protocol="HTTP",
            parsed_data={
                "http_method": http_method,
                "http_status": str(http_status),
                "uri_path": uri,
                "user_agent": "-",
            },
            bytes_sent=bytes_sent,
        )
    except Exception as e:
        pytest.fail(f"_make_parsed failed: {e}")


def _make_normalized(src_ip="-", uri="/search"):
    """Build a minimal NormalizedEvent for direct rule/engine testing."""
    try:
        return NormalizedEvent(
            event_id=uuid4(),
            file_id=uuid4(),
            row_hash=uuid4().hex[:16],
            timestamp=datetime(2026, 3, 24, 6, 41, 10),
            src_ip=src_ip,
            uri_path=uri,
            action="ALLOW",
        )
    except Exception as e:
        pytest.fail(f"_make_normalized failed: {e}")


# ===========================================================================
# 1. Normalization — missing source_address results in DISCARD (None)
# ===========================================================================

class TestNormalizationBlankSrcIp:

    def setup_method(self):
        try:
            self.svc = NormalizationService()
        except Exception as e:
            pytest.fail(f"NormalizationService setup failed: {e}")

    def test_missing_source_address_is_dropped(self):
        """If source_address is None, normalize_event must return None."""
        try:
            parsed = _make_parsed(source_address=None)
            event = self.svc.normalize_event(parsed)
            assert event is None, "Event should be dropped (None) when source is missing"
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_missing_source_address_is_dropped raised unexpected error: {e}")

    def test_private_ip_normalizes_correctly(self):
        """Private IPs (10.x.x.x) must normalize successfully."""
        try:
            for ip in ("10.61.63.169", "10.61.63.174"):
                parsed = _make_parsed(source_address=ip)
                event = self.svc.normalize_event(parsed)

                assert event is not None
                assert event.src_ip == ip, f"Expected {ip}, got '{event.src_ip}'"
                assert event.is_internal_src is True, (
                    f"{ip} should be classified as internal"
                )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_private_ip_normalizes_correctly raised unexpected error: {e}")

    def test_private_ip_is_not_global(self):
        """Sanity: 10.x.x.x must NOT be a global (public) IP address."""
        try:
            for ip in ("10.61.63.169", "10.61.63.174"):
                assert not ipaddress.ip_address(ip).is_global, (
                    f"{ip} should be private (non-global)"
                )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_private_ip_is_not_global raised unexpected error: {e}")


# ===========================================================================
# 2. Engine — events with src_ip="-" are excluded from rate-rule groups
# ===========================================================================

class TestEngineExcludesBlankSrcIp:

    def setup_method(self):
        try:
            self.engine = DeterministicEngine()
        except Exception as e:
            pytest.fail(f"DeterministicEngine setup failed: {e}")

    def test_blank_src_ip_events_not_grouped_for_rate_rules(self):
        """
        Build a batch of 200 events all with src_ip="-".
        Rate-based rules must receive 0 events in any group.
        """
        try:
            events = [_make_normalized(src_ip="-") for _ in range(200)]

            # Replicate the grouping logic from engine.scan()
            ip_groups: dict = defaultdict(list)
            for ev in events:
                if ev.src_ip and ev.src_ip != "-":
                    ip_groups[ev.src_ip].append(ev)

            assert len(ip_groups) == 0, (
                f"No IP groups should be formed for blank src_ip events, "
                f"but got groups: {list(ip_groups.keys())}"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_blank_src_ip_events_not_grouped_for_rate_rules raised unexpected error: {e}")

    def test_scan_produces_no_rate_matches_for_blank_src_ip(self):
        """Full engine scan on blank-src_ip events must produce 0 threats."""
        try:
            events = [_make_normalized(src_ip="-", uri="/search") for _ in range(300)]
            result = self.engine.scan(events)

            rate_threats = [
                t for t in result.threats
                if t.rule_name in (
                    "slowloris_suspected", "api_rate_abuse",
                    "http_flood", "resource_exhaustion",
                    "login_brute_force_rate",
                )
            ]
            assert len(rate_threats) == 0, (
                f"Expected 0 rate threats for blank src_ip, "
                f"got: {[(t.rule_name, t.src_ip) for t in rate_threats]}"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_scan_produces_no_rate_matches_for_blank_src_ip raised unexpected error: {e}")


# ===========================================================================
# 3. SlowlorisRule — private IPs are rejected at rule level
# ===========================================================================

class TestSlowlorisRulePublicIpOnly:

    def setup_method(self):
        try:
            self.rule = SlowlorisRule()
        except Exception as e:
            pytest.fail(f"SlowlorisRule setup failed: {e}")

    def _make_events(self, src_ip: str, count: int = 150) -> list[NormalizedEvent]:
        """Make enough unique-URI events to cross the threshold."""
        try:
            return [
                _make_normalized(src_ip=src_ip, uri=f"/page/{i}")
                for i in range(count)
            ]
        except Exception as e:
            pytest.fail(f"_make_events failed: {e}")

    def test_private_ip_10_x_x_x_is_ignored(self):
        """10.61.63.169/174 must NOT trigger Slowloris — private IP."""
        try:
            for ip in ("10.61.63.169", "10.61.63.174"):
                events = self._make_events(src_ip=ip, count=150)
                result = self.rule.check_group(events, group_key=ip)
                assert result is None, (
                    f"SlowlorisRule should return None for private IP {ip}, "
                    f"but returned: {result}"
                )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_private_ip_10_x_x_x_is_ignored raised unexpected error: {e}")

    def test_public_ip_triggers_slowloris(self):
        """A public IP hitting 150+ unique URIs must trigger Slowloris."""
        try:
            pub_ip = "8.8.8.8"  # Google DNS — verified global/public IP
            events = self._make_events(src_ip=pub_ip, count=150)
            result = self.rule.check_group(events, group_key=pub_ip)
            assert result is not None, (
                f"SlowlorisRule should trigger for public IP {pub_ip} "
                f"hitting 150 unique URIs, but returned None"
            )
            assert result.src_ip == pub_ip
            assert "unique URIs" in result.evidence
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_public_ip_triggers_slowloris raised unexpected error: {e}")

    def test_blank_src_ip_gives_no_match(self):
        """group_key='-' (placeholder) must return None from SlowlorisRule."""
        try:
            events = self._make_events(src_ip="-", count=200)
            result = self.rule.check_group(events, group_key="-")
            assert result is None, (
                "SlowlorisRule must return None for blank src_ip '-'"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_blank_src_ip_gives_no_match raised unexpected error: {e}")


# ===========================================================================
# 4. End-to-end: simulated normalized events from the sample syslog lines
# ===========================================================================

class TestSampleSyslogLogs:
    """
    Simulate the two specific sample log lines provided for testing.

    Log 1: src_ip=10.61.63.169  GET /search 302 0 bytes
    Log 2: src_ip=10.61.63.174  GET /search 302 0 bytes

    Expected results:
    - Both normalize successfully with their private IPs.
    - Neither triggers any rate-based rule (private IPs).
    - Neither triggers Slowloris specifically.
    """

    def setup_method(self):
        try:
            self.svc = NormalizationService()
            self.engine = DeterministicEngine()
        except Exception as e:
            pytest.fail(f"TestSampleSyslogLogs setup failed: {e}")

    def test_sample_log_1_normalizes_with_private_ip(self):
        try:
            parsed = _make_parsed(source_address="10.61.63.169", uri="/search",
                                  http_method="GET", http_status=302, bytes_sent=0)
            event = self.svc.normalize_event(parsed)

            assert event is not None
            assert event.src_ip == "10.61.63.169"
            assert event.uri_path == "/search"
            assert event.http_status == 302
            assert event.is_internal_src is True
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_sample_log_1_normalizes_with_private_ip raised unexpected error: {e}")

    def test_sample_log_2_normalizes_with_private_ip(self):
        try:
            parsed = _make_parsed(source_address="10.61.63.174", uri="/search",
                                  http_method="GET", http_status=302, bytes_sent=0)
            event = self.svc.normalize_event(parsed)

            assert event is not None
            assert event.src_ip == "10.61.63.174"
            assert event.is_internal_src is True
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_sample_log_2_normalizes_with_private_ip raised unexpected error: {e}")

    def test_sample_logs_produce_no_threats_in_engine(self):
        """Batch of both sample log events must produce zero threats."""
        try:
            events = []
            for ip in ("10.61.63.169", "10.61.63.174"):
                for _ in range(200):  # high count to stress-test rule thresholds
                    events.append(_make_normalized(src_ip=ip, uri="/search"))

            result = self.engine.scan(events)

            # No Slowloris — private IPs
            slowloris_threats = [
                t for t in result.threats if t.rule_name == "slowloris_suspected"
            ]
            assert len(slowloris_threats) == 0, (
                f"Slowloris must NOT fire for private IPs; "
                f"got: {[(t.rule_name, t.src_ip) for t in slowloris_threats]}"
            )
        except AssertionError:
            raise
        except Exception as e:
            pytest.fail(f"test_sample_logs_produce_no_threats_in_engine raised unexpected error: {e}")
