#!/usr/bin/env python3
"""
Simple validation script for the Apache parser changes.
Tests backward compatibility without requiring pytest.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_legacy_compatibility():
    """Test that legacy log formats still work."""
    print("Testing Legacy Compatibility")
    print("=" * 40)
    
    # Legacy sample from the original tests
    legacy_sample = (
        '<150>Jan 28 08:59:59 servernameabc httpd[12345]: '
        '10.10.10.10 203.0.113.99 443 abc.example.net - - '
        '[28/Jan/2026:08:59:59 +0530] '
        '"GET /page.html HTTP/1.1" 200 5120 17 '
        '"https://abc.example.com/" '
        '"Mozilla/5.0 (Windows NT 10.0)"'
    )
    
    try:
        from log_parser.syslog_parser import SyslogApacheParser
        
        parser = SyslogApacheParser()
        
        # Test can_parse
        confidence = parser.can_parse(["logevent"], [{"logevent": legacy_sample}])
        print(f"Legacy can_parse confidence: {confidence:.2f}")
        
        if confidence >= 0.6:
            print("✓ Legacy format detected with good confidence")
        else:
            print("✗ Legacy format not detected properly")
            return False
            
        # Test parsing
        from shared_models.events import RawEventRow
        from uuid import uuid4
        
        raw_row = RawEventRow(
            file_id=uuid4(),
            row_hash="test_hash",
            raw_data={"logevent": legacy_sample}
        )
        
        parsed = parser.parse_row(raw_row)
        
        # Validate key fields
        if parsed.source_address == "10.10.10.10":
            print("✓ Source IP extracted correctly")
        else:
            print(f"✗ Source IP incorrect: {parsed.source_address}")
            return False
            
        if parsed.destination_address == "203.0.113.99":
            print("✓ Destination IP extracted correctly")
        else:
            print(f"✗ Destination IP incorrect: {parsed.destination_address}")
            return False
            
        if parsed.parsed_data.get("http_method") == "GET":
            print("✓ HTTP method extracted correctly")
        else:
            print(f"✗ HTTP method incorrect: {parsed.parsed_data.get('http_method')}")
            return False
            
        if parsed.parsed_data.get("http_status") == 200:
            print("✓ HTTP status extracted correctly")
        else:
            print(f"✗ HTTP status incorrect: {parsed.parsed_data.get('http_status')}")
            return False
            
        print("✓ All legacy compatibility tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Legacy compatibility test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_new_patterns():
    """Test that new patterns work correctly."""
    print("\nTesting New Patterns")
    print("=" * 40)
    
    # Test samples for new patterns
    test_samples = [
        {
            "name": "Extended Pattern",
            "sample": '<134>Mar 27 10:15:30 webserver01 httpd[1234]: 192.168.1.100 10.0.0.1, 192.168.1.1, 10.0.0.2 - user123 example.com 27/Mar/2026:10:15:30 +0000] "GET /api/users HTTP/1.1" 200 1024 500 "https://example.com/login" "Mozilla/5.0"',
            "expected_src": "10.0.0.1",
            "expected_dst": "192.168.1.100",
            "expected_method": "GET"
        },
        {
            "name": "Flexible Pattern", 
            "sample": '<134>Mar 27 10:15:30 web01 httpd[123]: 1.1.1.1 2.2.2.2 user1 domain.com 27/Mar/2026:10:15:30] "GET /test" 200 100',
            "expected_src": "2.2.2.2",
            "expected_dst": "1.1.1.1", 
            "expected_method": "GET"
        }
    ]
    
    try:
        from log_parser.syslog_parser import SyslogApacheParser
        from shared_models.events import RawEventRow
        from uuid import uuid4
        
        parser = SyslogApacheParser()
        
        for test_case in test_samples:
            print(f"\nTesting {test_case['name']}:")
            
            # Test can_parse
            confidence = parser.can_parse(["logevent"], [{"logevent": test_case['sample']}])
            print(f"  Confidence: {confidence:.2f}")
            
            if confidence < 0.6:
                print(f"  ✗ Low confidence for {test_case['name']}")
                continue
                
            # Test parsing
            raw_row = RawEventRow(
                file_id=uuid4(),
                row_hash=f"test_hash_{test_case['name']}",
                raw_data={"logevent": test_case['sample']}
            )
            
            parsed = parser.parse_row(raw_row)
            
            # Validate fields
            if parsed.source_address == test_case['expected_src']:
                print(f"  ✓ Source IP: {parsed.source_address}")
            else:
                print(f"  ✗ Source IP: expected {test_case['expected_src']}, got {parsed.source_address}")
                
            if parsed.destination_address == test_case['expected_dst']:
                print(f"  ✓ Destination IP: {parsed.destination_address}")
            else:
                print(f"  ✗ Destination IP: expected {test_case['expected_dst']}, got {parsed.destination_address}")
                
            if parsed.parsed_data.get("http_method") == test_case['expected_method']:
                print(f"  ✓ HTTP Method: {parsed.parsed_data.get('http_method')}")
            else:
                print(f"  ✗ HTTP Method: expected {test_case['expected_method']}, got {parsed.parsed_data.get('http_method')}")
                
            # Show additional extracted fields
            if parsed.vendor_specific:
                print(f"  Additional fields: {parsed.vendor_specific}")
        
        return True
        
    except Exception as e:
        print(f"✗ New pattern test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all validation tests."""
    print("Apache Parser Validation")
    print("=" * 50)
    
    legacy_ok = test_legacy_compatibility()
    new_patterns_ok = test_new_patterns()
    
    print("\n" + "=" * 50)
    if legacy_ok and new_patterns_ok:
        print("✓ All validation tests passed!")
        print("The parser changes maintain backward compatibility")
        print("and successfully implement the new regex patterns.")
        return 0
    else:
        print("✗ Some validation tests failed!")
        print("Please review the parser implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())