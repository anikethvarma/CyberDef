"""
CSV-based GeoIP Enrichment Service

Uses local geoip2-ipv4.csv file for IP geolocation.
No external dependencies or downloads needed.
"""

from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
from typing import Optional, Dict, List, Tuple

from core.logging import get_logger
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)

# Global singleton instance
_geoip_instance: Optional['CSVGeoIPService'] = None


class CSVGeoIPService:
    """
    CSV-based GeoIP enrichment service using local CSV file.
    
    CSV Format: network,geoname_id,continent_code,continent_name,country_iso_code,country_name,is_anonymous_proxy,is_satellite_provider
    Example: 1.0.0.0/24,2077456,OC,Oceania,AU,Australia,0,0
    """

    def __init__(self, csv_path: Optional[Path] = None):
        # Check multiple possible locations for the CSV file
        possible_paths = [
            csv_path or Path("enrichment/geoip2-ipv4.csv"),
            Path("data/geoip2-ipv4.csv"),
            Path("geoip2-ipv4.csv"),
        ]
        
        self.csv_path = None
        self.networks: List[Tuple[ipaddress.IPv4Network, Dict[str, str]]] = []
        self.network_addresses: List[int] = []  # Precomputed network addresses for faster binary search
        self.enabled = False
        self._lookup_cache: Dict[str, Optional[Dict[str, str]]] = {}  # IP lookup cache
        
        # Find the CSV file
        for path in possible_paths:
            if path.exists():
                self.csv_path = path
                break
        
        if not self.csv_path:
            logger.warning(f"CSV GeoIP database not found in: {[str(p) for p in possible_paths]}")
            logger.warning("Geographic enrichment disabled.")
            return
        
        # Try to load the database
        if self._load_database():
            self.enabled = True
            logger.info(f"CSV GeoIP database loaded from {self.csv_path}: {len(self.networks)} networks")
        else:
            logger.warning("Failed to load CSV GeoIP database. Geographic enrichment disabled.")

    def _load_database(self) -> bool:
        """Load the CSV database from local file."""
        
        if not self.csv_path.exists():
            logger.error(f"CSV GeoIP database not found: {self.csv_path}")
            return False
        
        # Load the CSV data
        try:
            return self._parse_csv()
        except Exception as e:
            logger.error(f"Failed to load CSV GeoIP database: {e}")
            return False

    def _parse_csv(self) -> bool:
        """Parse the CSV file and build the network lookup table."""
        logger.info(f"Parsing CSV GeoIP database from {self.csv_path}...")
        
        networks = []
        
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row_num, row in enumerate(reader, 1):
                    try:
                        # Parse network CIDR
                        network = ipaddress.IPv4Network(row['network'], strict=False)
                        
                        # Extract geo data
                        geo_data = {
                            'continent_code': row.get('continent_code', ''),
                            'continent_name': row.get('continent_name', ''),
                            'country_iso_code': row.get('country_iso_code', ''),
                            'country_name': row.get('country_name', ''),
                            'is_anonymous_proxy': row.get('is_anonymous_proxy', '0') == '1',
                            'is_satellite_provider': row.get('is_satellite_provider', '0') == '1'
                        }
                        
                        networks.append((network, geo_data))
                        
                        # Log progress every 100k rows
                        if row_num % 100000 == 0:
                            logger.info(f"Parsed {row_num} networks...")
                            
                    except Exception as e:
                        logger.debug(f"Skipping invalid row {row_num}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse CSV: {e}")
            return False
        
        # Sort networks by network address for efficient lookup
        networks.sort(key=lambda x: x[0].network_address)
        self.networks = networks
        
        # Precompute network addresses for faster binary search
        self.network_addresses = [net[0].network_address for net in self.networks]
        
        logger.info(f"Loaded {len(self.networks)} IP networks from CSV")
        return True

    def _lookup_ip(self, ip_str: str) -> Optional[Dict[str, str]]:
        """Look up geographic data for an IP address using binary search and caching."""
        # Check cache first
        if ip_str in self._lookup_cache:
            return self._lookup_cache[ip_str]
        
        try:
            ip_int = int(ipaddress.IPv4Address(ip_str))
            
            # Binary search through sorted network addresses
            left, right = 0, len(self.network_addresses) - 1
            result = None
            
            while left <= right:
                mid = (left + right) // 2
                network, geo_data = self.networks[mid]
                net_addr = self.network_addresses[mid]
                
                # Check if IP is in this network
                if ip_int >= net_addr and ip_int <= int(network.broadcast_address):
                    result = geo_data
                    break
                elif ip_int < net_addr:
                    right = mid - 1
                else:
                    left = mid + 1
            
            # Cache result
            self._lookup_cache[ip_str] = result
            return result
            
        except Exception as e:
            logger.debug(f"IP lookup failed for {ip_str}: {e}")
            self._lookup_cache[ip_str] = None
            return None

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich single event with geographic data."""
        if not self.enabled:
            return event
        
        # Only enrich external IPs
        if event.is_internal_src is False and event.src_ip:
            self._add_geo_data(event, event.src_ip, "src")
        
        if event.is_internal_dst is False and event.dst_ip:
            self._add_geo_data(event, event.dst_ip, "dst")
        
        return event

    def enrich_batch(self, events: List[NormalizedEvent]) -> List[NormalizedEvent]:
        """Enrich batch of events with geographic data (optimized for unique IPs)."""
        if not self.enabled or not events:
            return events
        
        # Extract unique external IPs to avoid redundant lookups
        unique_ips = set()
        for event in events:
            if event.is_internal_src is False and event.src_ip:
                unique_ips.add(event.src_ip)
            if event.is_internal_dst is False and event.dst_ip:
                unique_ips.add(event.dst_ip)
        
        # Pre-lookup all unique IPs (with caching)
        ip_geo_map = {}
        for ip in unique_ips:
            ip_geo_map[ip] = self._lookup_ip(ip)
        
        # Apply cached results to all events
        for event in events:
            if event.is_internal_src is False and event.src_ip and event.src_ip in ip_geo_map:
                geo_data = ip_geo_map[event.src_ip]
                if geo_data:
                    event.geo_country = geo_data.get('country_name') or None
                    event.geo_region = None
                    event.geo_city = None
                    event.geo_latitude = None
                    event.geo_longitude = None
            
            if event.is_internal_dst is False and event.dst_ip and event.dst_ip in ip_geo_map:
                geo_data = ip_geo_map[event.dst_ip]
                if geo_data:
                    event.geo_country = geo_data.get('country_name') or None
                    event.geo_region = None
                    event.geo_city = None
                    event.geo_latitude = None
                    event.geo_longitude = None
        
        logger.info(f"CSV GeoIP enriched batch | events={len(events)}, unique_ips={len(unique_ips)}, cache_hits={len(self._lookup_cache)}")
        return events

    def _add_geo_data(self, event: NormalizedEvent, ip: str, ip_type: str):
        """Add geographic data for an IP address."""
        geo_data = self._lookup_ip(ip)
        
        if geo_data:
            # Map CSV data to event fields
            event.geo_country = geo_data.get('country_name') or None
            event.geo_region = None  # CSV doesn't have region/state data
            event.geo_city = None    # CSV doesn't have city data
            event.geo_latitude = None   # CSV doesn't have coordinates
            event.geo_longitude = None  # CSV doesn't have coordinates
            
            logger.debug(f"CSV GeoIP enriched {ip_type} IP {ip}: {event.geo_country} ({geo_data.get('country_iso_code')})")
        else:
            logger.debug(f"CSV GeoIP: No data found for {ip_type} IP {ip}")

    def test_ip(self, ip: str) -> Dict:
        """Test GeoIP lookup for a specific IP (for debugging)."""
        if not self.enabled:
            return {"error": "CSV GeoIP not enabled"}
        
        geo_data = self._lookup_ip(ip)
        
        if geo_data:
            return {
                "ip": ip,
                "country": geo_data.get('country_name'),
                "country_code": geo_data.get('country_iso_code'),
                "continent": geo_data.get('continent_name'),
                "continent_code": geo_data.get('continent_code'),
                "is_anonymous_proxy": geo_data.get('is_anonymous_proxy'),
                "is_satellite_provider": geo_data.get('is_satellite_provider')
            }
        else:
            return {"error": f"No CSV GeoIP data found for {ip}"}

    def get_stats(self) -> Dict:
        """Get CSV GeoIP service statistics."""
        return {
            "enabled": self.enabled,
            "csv_path": str(self.csv_path) if self.csv_path else "Not found",
            "csv_exists": self.csv_path.exists() if self.csv_path else False,
            "networks_loaded": len(self.networks)
        }

    def close(self):
        """Clean up resources."""
        self.networks.clear()
        self._lookup_cache.clear()
        self.enabled = False

    def __del__(self):
        self.close()


def get_geoip_service() -> CSVGeoIPService:
    """Get or create singleton GeoIP service instance (loads CSV only once)."""
    global _geoip_instance
    if _geoip_instance is None:
        _geoip_instance = CSVGeoIPService()
    return _geoip_instance


# Alias for backward compatibility
GeoIPEnrichmentService = CSVGeoIPService