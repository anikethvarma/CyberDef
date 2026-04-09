
import sys
import os
from datetime import datetime
from uuid import uuid4

# Add the project root to sys.path
sys.path.append(os.getcwd())

from shared_models.events import NormalizedEvent, EventAction, NetworkProtocol
from rules_engine.rules_bot_cve import SlowlorisRule, Rapid404Rule, ResourceExhaustionRule
from rules_engine.rules_auth import CSRFIndicatorRule
from normalization.service import NormalizationService, ParsedEvent

def test_slowloris():
    print("Testing Slowloris...")
    rule = SlowlorisRule()
    events = []
    # Create 101 events with low bytes, low unique URLs, and high duration
    for i in range(101):
        events.append(NormalizedEvent(
            file_id=uuid4(),
            row_hash=str(i),
            timestamp=datetime.utcnow(),
            src_ip="1.2.3.4",
            action=EventAction.ALLOW,
            bytes_sent=400,
            duration_ms=40000 if i % 2 == 0 else 0, # Avg duration for > 0 will be 40000
            uri_path="/index.html" if i % 50 == 0 else "/test.html" # 2 unique URLs
        ))
    
    match = rule.check_group(events, "1.2.3.4")
    if match:
        print(f"SUCCESS: Slowloris detected. Evidence: {match.evidence}")
    else:
        print("FAILURE: Slowloris NOT detected")

def test_rapid404():
    print("\nTesting Rapid404...")
    rule = Rapid404Rule()
    
    # Test Public IP triggering
    events = []
    for i in range(51):
        events.append(NormalizedEvent(
            file_id=uuid4(),
            row_hash=str(i),
            timestamp=datetime.utcnow(),
            src_ip="8.8.8.8",
            action=EventAction.DENY,
            http_status=404,
            uri_path=f"/path_{i}"
        ))
    
    match = rule.check_group(events, "8.8.8.8")
    if match:
        print(f"SUCCESS: Rapid404 detected on Public IP. Evidence: {match.evidence}")
    else:
        print("FAILURE: Rapid404 NOT detected on Public IP")

    # Test Private IP suppression
    match_private = rule.check_group(events, "192.168.1.1")
    if not match_private:
        print("SUCCESS: Rapid404 suppressed on Private IP")
    else:
        print("FAILURE: Rapid404 triggered on Private IP")

    # Test success count constraint
    events_with_success = events + [
        NormalizedEvent(file_id=uuid4(), row_hash="s1", timestamp=datetime.utcnow(), src_ip="8.8.8.8", action=EventAction.ALLOW, http_status=200, uri_path="/"),
        NormalizedEvent(file_id=uuid4(), row_hash="s2", timestamp=datetime.utcnow(), src_ip="8.8.8.8", action=EventAction.ALLOW, http_status=200, uri_path="/")
    ]
    match_failed = rule.check_group(events_with_success, "8.8.8.8")
    if not match_failed:
        print("SUCCESS: Rapid404 suppressed due to >1 success code")
    else:
        print("FAILURE: Rapid404 triggered despite >1 success code")

def test_resource_exhaustion():
    print("\nTesting Resource Exhaustion...")
    rule = ResourceExhaustionRule()
    events = []
    for i in range(31):
        events.append(NormalizedEvent(
            file_id=uuid4(),
            row_hash=str(i),
            timestamp=datetime.utcnow(),
            src_ip="1.2.3.4",
            action=EventAction.ALLOW,
            uri_path="/search/results"
        ))
    
    match = rule.check_group(events, "1.2.3.4")
    if match:
        print(f"SUCCESS: Resource Exhaustion detected. Evidence: {match.evidence}")
    else:
        print("FAILURE: Resource Exhaustion NOT detected")

def test_csrf_exclusions():
    print("\nTesting CSRF Exclusions...")
    rule = CSRFIndicatorRule()
    
    def get_event(referrer):
        return NormalizedEvent(
            file_id=uuid4(),
            row_hash="1",
            timestamp=datetime.utcnow(),
            src_ip="1.2.3.4",
            action=EventAction.ALLOW,
            http_method="POST",
            referrer=referrer,
            original_message="missing token"
        )

    # test excluded domains
    exclude_list = [
        "https://myapps.tcsapps.com/home",
        "https://login.microsoftonline.com/",
        "https://s1-eu.ariba.com/test",
        "https://t.mediassist.in"
    ]
    
    all_passed = True
    for domain in exclude_list:
        match = rule.match(get_event(domain))
        if match:
            print(f"FAILURE: CSRF triggered for excluded domain: {domain}")
            all_passed = False
    
    if all_passed:
        print("SUCCESS: All CSRF exclusions correctly ignored")

def test_ip_prioritization():
    print("\nTesting IP Prioritization...")
    service = NormalizationService()
    
    # Mock ParsedEvent
    parsed = ParsedEvent(
        file_id=uuid4(),
        row_hash="1",
        source_address="1.1.1.1",
        destination_address="2.2.2.2",
        action="ALLOW",
        protocol="HTTP",
        timestamp=datetime.utcnow()
    )
    
    normalized = service.normalize_event(parsed)
    if normalized.src_ip == "2.2.2.2" and normalized.dst_ip is None:
        print("SUCCESS: IP prioritization logic applied (dst_ip became src_ip)")
    else:
        print(f"FAILURE: IP prioritization logic NOT applied. src={normalized.src_ip}, dst={normalized.dst_ip}")

if __name__ == "__main__":
    try:
        test_slowloris()
        test_rapid404()
        test_resource_exhaustion()
        test_csrf_exclusions()
        test_ip_prioritization()
    except Exception as e:
        print(f"Error during verification: {e}")
        import traceback
        traceback.print_exc()
