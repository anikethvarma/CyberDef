"""
GeoIP Enrichment Service - Working Implementation

Enriches events with geographic information for external IPs.
Replace the current geoip_service.py with this implementation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from core.config import get_settings
from core.logging import get_logger
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)

# Try to import geoip2, fall back to stub if not available
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 module not installed. Install with: pip install geoip2")


class GeoIPEnrichmentService:
    """
    GeoIP enrichment service using MaxMind GeoLite2 database.
    Falls back to stub behavior if geoip2 module or database unavailable.
    """

    # Standard database locations to check
    DB_PATHS = [
        Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"),
        Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
        Path("./data/GeoLite2-City.mmdb"),
        Path("~/.local/share/GeoIP/GeoLite2-City.mmdb").expanduser(),
    ]

    def __init__(self, db_path: Optional[Path] = None):
        self.reader = None
        self.enabled = False
        
        if not GEOIP2_AVAILABLE:
            logger.info("GeoIP enrichment disabled (geoip2 module not available)")
            return
        
        # Find database
        if db_path and db_path.exists():
            db_file = db_path
        else:
            db_file = self._find_database()
        
        if db_file:
            try:
                self.reader = geoip2.database.Reader(str(db_file))
                self.enabled = True
                logger.info(f"GeoIP database loaded: {db_file}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database {db_file}: {e}")
                self.reader = None
        else:
            logger.warning("GeoIP database not found. Geographic enrichment disabled.")
            logger.info("To enable GeoIP:")
            logger.info("1. Install geoip2: pip install geoip2")
            logger.info("2. Download GeoLite2-City.mmdb to one of:")
            for path in self.DB_PATHS:
                logger.info(f"   - {path}")
            logger.info("3. See docs/GEOIP_SETUP.md for detailed instructions")

    def _find_database(self) -> Optional[Path]:
        """Find GeoIP database in standard locations."""
        for path in self.DB_PATHS:
            if path.exists():
                return path
        return None

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich single event with geographic data."""
        if not self.enabled or not self.reader:
            return event
        
        # Only enrich external IPs
        if event.is_internal_src is False and event.src_ip:
            self._add_geo_data(event, event.src_ip, "src")
        
        if event.is_internal_dst is False and event.dst_ip:
            self._add_geo_data(event, event.dst_ip, "dst")
        
        return event

    def enrich_batch(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        """Enrich batch of events with geographic data."""
        if not self.enabled or not self.reader:
            return events
        
        enriched = []
        external_ips_processed = 0
        
        for event in events:
            original_event = event
            enriched_event = self.enrich_event(event)
            
            # Count external IPs processed
            if ((event.is_internal_src is False and event.src_ip) or 
                (event.is_internal_dst is False and event.dst_ip)):
                external_ips_processed += 1
            
            enriched.append(enriched_event)
        
        if external_ips_processed > 0:
            logger.debug(f"GeoIP enriched {external_ips_processed} external IPs in batch")
        
        return enriched

    def _add_geo_data(self, event: NormalizedEvent, ip: str, ip_type: str):
        """Add geographic data for an IP address."""
        try:
            response = self.reader.city(ip)
            
            # Add geographic data (only if we have valid data)
            if response.country.name:
                event.geo_country = response.country.name
            
            if response.subdivisions.most_specific.name:
                event.geo_region = response.subdivisions.most_specific.name
            
            if response.city.name:
                event.geo_city = response.city.name
            
            if response.location.latitude is not None:
                event.geo_latitude = float(response.location.latitude)
            
            if response.location.longitude is not None:
                event.geo_longitude = float(response.location.longitude)
            
            logger.debug(f"GeoIP enriched {ip_type} IP {ip}: {event.geo_country}, {event.geo_city}")
            
        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"GeoIP: No data found for {ip_type} IP {ip}")
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip_type} IP {ip}: {e}")

    def get_stats(self) -> dict:
        """Get GeoIP service statistics."""
        return {
            "enabled": self.enabled,
            "geoip2_available": GEOIP2_AVAILABLE,
            "database_loaded": self.reader is not None,
            "database_paths_checked": [str(p) for p in self.DB_PATHS]
        }

    def test_ip(self, ip: str) -> dict:
        """Test GeoIP lookup for a specific IP (for debugging)."""
        if not self.enabled or not self.reader:
            return {"error": "GeoIP not enabled"}
        
        try:
            response = self.reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.name,
                "region": response.subdivisions.most_specific.name,
                "city": response.city.name,
                "latitude": float(response.location.latitude) if response.location.latitude else None,
                "longitude": float(response.location.longitude) if response.location.longitude else None,
                "country_code": response.country.iso_code,
                "timezone": response.location.time_zone
            }
        except geoip2.errors.AddressNotFoundError:
            return {"error": f"No GeoIP data found for {ip}"}
        except Exception as e:
            return {"error": f"GeoIP lookup failed: {e}"}

    def close(self):
        """Close the database reader."""
        if self.reader:
            self.reader.close()
            self.reader = None
            self.enabled = False

    def __del__(self):
        self.close()