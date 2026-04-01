# Exact Code Changes Required

## File 1: main.py

### Change 1: Remove GeoIP enrichment block (Line ~230)

**REMOVE THIS ENTIRE BLOCK:**
```python
    # Enrich with GeoIP (singleton - loads CSV only once)
    from enrichment.geoip_service import get_geoip_service
    import time
    
    settings = get_settings()
    if settings.enable_geoip:
        geoip_start = time.time()
        geoip_svc = get_geoip_service()
        
        # Skip GeoIP if disabled or not available
        if geoip_svc.enabled:
            enriched_events = geoip_svc.enrich_batch(event_batch.events)
            geoip_elapsed = time.time() - geoip_start
            logger.info(f"GeoIP enrichment complete | time_ms={geoip_elapsed*1000:.1f}")
        else:
            enriched_events = event_batch.events
            logger.info("GeoIP enrichment skipped (database not available)")
    else:
        enriched_events = event_batch.events
        logger.info("GeoIP enrichment disabled (ENABLE_GEOIP=false)")
```

**REPLACE WITH:**
```python
    # Use normalized events directly (GeoIP removed for performance)
    enriched_events = event_batch.events
```

---

## File 2: shared_models/events.py

### Change 1: Remove GeoIP fields from NormalizedEvent class

**FIND THIS SECTION (around line 130):**
```python
    # Geographic data (for external IPs)
    geo_country: Optional[str] = None
    geo_region: Optional[str] = None
    geo_city: Optional[str] = None
    geo_latitude: Optional[float] = None
    geo_longitude: Optional[float] = None
```

**DELETE THESE 5 LINES ENTIRELY**

---

## File 3: normalization/service.py

### Change 1: Update IP validation logic in normalize_event() method

**FIND THIS SECTION (around line 100):**
```python
        # Extract and validate source IP (required)
        src_ip = self._normalize_ip(parsed.source_address)
        if not src_ip:
            logger.warning(
                f"Missing source IP | file_id={parsed.file_id}, row_hash={parsed.row_hash}"
            )
            self.normalization_errors += 1
            return None

        # Normalize destination IP (optional)
        dst_ip = self._normalize_ip(parsed.destination_address)
```

**REPLACE WITH:**
```python
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
        
        # If src_ip is missing, use dst_ip as primary actor
        if not src_ip:
            src_ip = dst_ip
            dst_ip = None
```

---

## File 4: core/config.py

### Change 1: Remove GeoIP config setting

**FIND THIS SECTION (around line 60):**
```python
    # Processing
    max_file_size_mb: int = 500
    chunk_time_window_minutes: int = 30
    max_events_per_batch: int = 10000
    
    # GeoIP Enrichment
    enable_geoip: bool = True  # Set to False to skip GeoIP enrichment for faster processing
    
    # Agent Configuration
```

**REPLACE WITH:**
```python
    # Processing
    max_file_size_mb: int = 500
    chunk_time_window_minutes: int = 30
    max_events_per_batch: int = 10000
    
    # Agent Configuration
```

---

## File 5: .env

### Change 1: Remove GeoIP config

**FIND THIS LINE AT THE END:**
```
# GeoIP Enrichment (set to false to skip for faster processing)
ENABLE_GEOIP=true
```

**DELETE THESE 2 LINES**

---

## Optional: Cleanup Files (Delete)

These files can be deleted to save space and reduce clutter:

1. `enrichment/geoip_service.py` (8.7 KB)
2. `enrichment/geoip_csv_service.py` (if exists)
3. `enrichment/geoip2-ipv4.csv` (31 MB) ← **Major space savings**
4. `GEOIP_OPTIMIZATION.md`
5. `GEOIP_QUICK_FIX.md`

---

## Summary of Changes

| File | Changes | Lines |
|------|---------|-------|
| main.py | Remove GeoIP block | ~20 lines |
| shared_models/events.py | Remove 5 fields | 5 lines |
| normalization/service.py | Update validation logic | ~15 lines |
| core/config.py | Remove 1 setting | 1 line |
| .env | Remove 2 lines | 2 lines |
| **Total** | **5 files** | **~43 lines** |

---

## Validation Checklist

After making changes:

- [ ] No syntax errors in modified files
- [ ] File uploads complete in ~5s (was 95s)
- [ ] No "GeoIP" messages in logs
- [ ] Logs with dst_ip only are processed
- [ ] Incidents still generated
- [ ] Reports still created
- [ ] No errors in application logs

---

## Rollback

If anything breaks:

```bash
git checkout main.py shared_models/events.py normalization/service.py core/config.py .env
```

All changes are reversible.
