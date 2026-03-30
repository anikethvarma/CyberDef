"""
CSV-based GeoIP Enrichment Service

Uses the GitHub geoip2-ipv4 CSV dataset for IP geolocation.
Much simpler than MaxMind binary format - no external dependencies needed.
"""

from __future__ import annotations

import csv
import ipaddress
import urllib.request
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import logging

from core.logging import get_logger
from shared_models.events import NormalizedEvent

logger = get_logger(__name__)


class CSVGeoIPService:
    """
    CSV-based GeoIP enrichment service using GitHub dataset.
    
    CSV Format: network,geoname_id,continent_code,continent_name,country_iso_code,country_name,is_anonymous_proxy,is_satellite_provider
    Example: 1.0.0.0/24,2077456,OC,Oceania,AU,Australia,0,0
    """

    def __init__(self, csv_path: Optional[Path] = None, auto_download: bool = True):
        self.csv_path = csv_path or Path("data/geoip2-ipv4.csv")
        self.networks: List[Tuple[ipaddress.IPv4Network, Dict[str, str]]] = []
        self.enabled = False
        
        # GitHub CSV URL
        self.csv_url = "https://raw.githubusercontent.com/datasets/geoip2-ipv4/refs/heads/main/data/geoip2-ipv4.csv"
        
        # Try to load the database
        if self._load_database(auto_download):
            self.enabled = True
            logger.info(f"CSV GeoIP database loaded: {len(self.networks)} networks")
        else:
            logger.warning("CSV GeoIP database not available. Geographic enrichment disabled.")

    def _load_database(self, auto_download: bool = True) -> bool:
        """Load the CSV database, downloading if necessary."""
        
        # Check if file exists
        if not self.csv_path.exists() and auto_download:
            logger.info("CSV GeoIP database not found. Downloading...")
            if not self._download_database():
                return False
        
        if not self.csv_path.exists():
            logger.error(f"CSV GeoIP database not found: {self.csv_path}")
            return False
        
        # Load the CSV data
        try:
            return self._parse_csv()
        except Exception as e:
            logger.error(f"Failed to load CSV GeoIP database: {e}")
            return False

    def _download_database(self) -> bool:
        """Download the CSV database from GitHub."""
        try:
            # Create data directory if it doesn't exist
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Downloading GeoIP CSV from {self.csv_url}")
            
            with urllib.request.urlopen(self.csv_url) as response:
                with open(self.csv_path, 'wb') as f:
                    # Download in chunks to handle large file
                    chunk_size = 8192
                    total_size = 0
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        total_size += len(chunk)
                        
                        # Log progress every 10MB
                        if total_size % (10 * 1024 * 1024) == 0:
                            logger.info(f"Downloaded {total_size // (1024 * 1024)}MB...")
            
            logger.info(f"Download complete: {total_size // (1024 * 1024)}MB")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download GeoIP CSV: {e}")
            return False

    def _parse_csv(self) -> bool:
        """Parse the CSV file and build the network lookup table."""
        logger.info("Parsing CSV GeoIP database...")
        
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
                        logger.warning(f"Skipping invalid row {row_num}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse CSV: {e}")
            return False
        
        # Sort networks by network address for efficient lookup
        networks.sort(key=lambda x: x[0].network_address)
        self.networks = networks
        
        logger.info(f"Loaded {len(self.networks)} IP networks")
        return True

    def _lookup_ip(self, ip_str: str) -> Optional[Dict[str, str]]:
        """Look up geographic data for an IP address."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            
            # Binary search through sorted networks
            for network, geo_data in self.networks:
                if ip in network:
                    return geo_data
            
            return None
            
        except Exception as e:
            logger.debug(f"IP lookup failed for {ip_str}: {e}")
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
        """Enrich batch of events with geographic data."""
        if not self.enabled:
            return events
        
        enriched = []
        external_ips_processed = 0
        
        for event in events:
            enriched_event = self.enrich_event(event)
            
            # Count external IPs processed
            if ((event.is_internal_src is False and event.src_ip) or 
                (event.is_internal_dst is False and event.dst_ip)):
                external_ips_processed += 1
            
            enriched.append(enriched_event)
        
        if external_ips_processed > 0:
            logger.debug(f"CSV GeoIP enriched {external_ips_processed} external IPs in batch")
        
        return enriched

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
            "csv_path": str(self.csv_path),
            "csv_exists": self.csv_path.exists(),
            "networks_loaded": len(self.networks),
            "csv_url": self.csv_url
        }

    def close(self):
        """Clean up resources."""
        self.networks.clear()
        self.enabled = False

    def __del__(self):
        self.close()


# Alias for backward compatibility
GeoIPEnrichmentService = CSVGeoIPService