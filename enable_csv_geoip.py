#!/usr/bin/env python3
"""
Enable CSV GeoIP by replacing the stubbed service.
"""

import shutil
from pathlib import Path

def enable_csv_geoip():
    """Replace the stubbed GeoIP service with CSV implementation."""
    
    print("Enabling CSV GeoIP Service")
    print("=" * 30)
    
    # File paths
    current_service = Path("enrichment/geoip_service.py")
    csv_service = Path("enrichment/geoip_csv_service.py")
    backup_service = Path("enrichment/geoip_service_stub.py")
    
    # Check if files exist
    if not current_service.exists():
        print(f"✗ Current service not found: {current_service}")
        return False
    
    if not csv_service.exists():
        print(f"✗ CSV service not found: {csv_service}")
        return False
    
    try:
        # Backup current service
        if current_service.exists():
            shutil.copy2(current_service, backup_service)
            print(f"✓ Backed up current service to: {backup_service}")
        
        # Replace with CSV service
        shutil.copy2(csv_service, current_service)
        print(f"✓ Replaced service with CSV implementation")
        
        # Verify the replacement
        with open(current_service, 'r') as f:
            content = f.read()
            if "CSVGeoIPService" in content:
                print(f"✓ CSV GeoIP service is now active")
                return True
            else:
                print(f"✗ Replacement failed - CSV service not detected")
                return False
                
    except Exception as e:
        print(f"✗ Error during replacement: {e}")
        return False

def show_next_steps():
    """Show what to do next."""
    print(f"\n" + "=" * 30)
    print("Next Steps:")
    print("1. Restart your application")
    print("2. CSV will auto-download on first use (~200MB)")
    print("3. External IPs will be geo-tagged with country data")
    print("4. Monitor logs for 'CSV GeoIP database loaded' message")
    print()
    print("Test with:")
    print("  python test_csv_geoip_standalone.py")
    print()
    print("Your external IP 167.103.89.9 will now get geographic data!")

if __name__ == "__main__":
    success = enable_csv_geoip()
    
    if success:
        show_next_steps()
        print(f"\n✅ CSV GeoIP enabled successfully!")
    else:
        print(f"\n❌ Failed to enable CSV GeoIP")
        print("Check the error messages above and try again.")