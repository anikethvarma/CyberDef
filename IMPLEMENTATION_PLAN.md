# Implementation Plan: Remove GeoIP & Add IP Validation

## Current State Analysis

### What's Currently Happening
1. **GeoIP Enrichment** - Takes 40-50s per file (major bottleneck)
   - Loads 31MB CSV with 1.5M networks
   - Looks up country for each external IP
   - Adds `geo_country`, `geo_region`, `geo_city` fields

2. **Event Validation** - Currently only checks for `src_ip`
   - Logs without `src_ip` are rejected (returns None)
   - Logs with only `dst_ip` are also rejected
   - No validation that events have meaningful IP pairs

### Problem Statement
- GeoIP is a **non-critical enrichment** taking significant time
- Current validation is too strict (rejects valid logs with only dst_ip)
- Need to **filter false positives** (logs with no source IP)

## Proposed Solution

### Phase 1: Remove GeoIP (Immediate - 40-50s savings)
**Goal**: Eliminate GeoIP enrichment entirely

**Changes**:
1. Remove GeoIP service instantiation from `main.py`
2. Remove GeoIP enrichment call from pipeline
3. Remove GeoIP fields from `NormalizedEvent` model
4. Remove `ENABLE_GEOIP` config
5. Delete GeoIP-related files (optional, can keep for future)

**Impact**: 
- Saves 40-50s per file
- Reduces memory usage (no 1.5M network list in memory)
- Simplifies pipeline

### Phase 2: Improve IP Validation (Immediate - Better data quality)
**Goal**: Filter out false positives while accepting valid logs

**Current Logic**:
```python
src_ip = normalize_ip(parsed.source_address)
if not src_ip:
    return None  # Reject
```

**Proposed Logic**:
```python
src_ip = normalize_ip(parsed.source_address)
dst_ip = normalize_ip(parsed.destination_address)

# Valid cases:
# 1. Has src_ip AND dst_ip (complete connection)
# 2. Has src_ip only (outbound/internal activity)
# 3. Has dst_ip only (inbound/external activity)

# Invalid cases (false positives):
# 1. Has neither src_ip nor dst_ip (meaningless)
# 2. Both are None or invalid

if not src_ip and not dst_ip:
    return None  # Reject - no meaningful IP data

# Accept if at least one valid IP exists
```

**Implementation Location**: `normalization/service.py` → `normalize_event()` method

**Code Change**:
```python
# Extract and validate IPs
src_ip = self._normalize_ip(parsed.source_address)
dst_ip = self._normalize_ip(parsed.destination_address)

# Require at least one valid IP (not both missing)
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

**Impact**:
- Accepts logs with only `dst_ip` (inbound traffic)
- Rejects logs with neither IP (true false positives)
- Better coverage of threat patterns

### Phase 3: Restore Original Libraries (Cleanup)
**Goal**: Remove GeoIP dependencies, restore clean state

**Changes**:
1. Remove `geoip2` library imports (if any)
2. Remove `maxminddb` library imports (if any)
3. Keep only essential libraries:
   - `ipaddress` (for IP validation)
   - `csv` (for parsing)
   - `pydantic` (for models)
   - `fastapi` (for API)

**Files to Clean**:
- `enrichment/geoip_service.py` - Can delete or keep as stub
- `enrichment/geoip_csv_service.py` - Can delete
- `enrichment/geoip2-ipv4.csv` - Can delete (31MB saved)
- `GEOIP_OPTIMIZATION.md` - Can delete
- `GEOIP_QUICK_FIX.md` - Can delete

**pyproject.toml**:
- Remove `geoip2` dependency (if present)
- Remove `maxminddb` dependency (if present)

## Implementation Steps

### Step 1: Remove GeoIP from Pipeline (5 min)
1. Edit `main.py` line ~230
2. Remove GeoIP enrichment block
3. Remove timing instrumentation for GeoIP
4. Remove config check for `enable_geoip`

### Step 2: Update NormalizedEvent Model (5 min)
1. Edit `shared_models/events.py`
2. Remove GeoIP fields:
   - `geo_country`
   - `geo_region`
   - `geo_city`
   - `geo_latitude`
   - `geo_longitude`

### Step 3: Improve IP Validation (10 min)
1. Edit `normalization/service.py` → `normalize_event()`
2. Change validation logic to accept either src_ip OR dst_ip
3. If src_ip missing, use dst_ip as primary
4. Update logging to reflect new validation

### Step 4: Remove Config (2 min)
1. Edit `core/config.py`
2. Remove `enable_geoip: bool = True`
3. Edit `.env`
4. Remove `ENABLE_GEOIP=true`

### Step 5: Cleanup (Optional, 5 min)
1. Delete `enrichment/geoip_service.py`
2. Delete `enrichment/geoip_csv_service.py`
3. Delete `enrichment/geoip2-ipv4.csv` (31MB)
4. Delete optimization docs

## Expected Outcomes

### Performance Improvement
| Metric | Before | After | Savings |
|--------|--------|-------|---------|
| File 1 | 95s | 45s | 50s |
| File 2 | 95s | 5s | 90s |
| File 3 | 95s | 5s | 90s |
| **Total (3 files)** | **285s** | **55s** | **230s (81%)** |

### Data Quality Improvement
| Scenario | Before | After |
|----------|--------|-------|
| Logs with src_ip + dst_ip | ✓ Accepted | ✓ Accepted |
| Logs with src_ip only | ✓ Accepted | ✓ Accepted |
| Logs with dst_ip only | ✗ Rejected | ✓ Accepted |
| Logs with neither | ✗ Rejected | ✗ Rejected |

### Code Simplification
- Remove 300+ lines of GeoIP code
- Remove 1 external dependency
- Reduce memory footprint by 31MB (CSV) + 50MB (loaded data)
- Simpler pipeline logic

## Risk Assessment

### Low Risk
- GeoIP is enrichment, not core analysis
- Agents don't depend on geo_country field
- Can be re-added later if needed

### Mitigation
- Keep GeoIP files in git history (can restore)
- Keep optimization docs for reference
- Test with sample files before/after

## Testing Strategy

### Before Changes
```bash
# Upload file, note timing
curl -X POST http://localhost:8000/api/v1/files/upload -F "file=@test.csv"
# Expected: ~95s
```

### After Changes
```bash
# Upload same file
curl -X POST http://localhost:8000/api/v1/files/upload -F "file=@test.csv"
# Expected: ~5s (90s faster)

# Check logs for:
# - No "CSV GeoIP database loaded" message
# - No "GeoIP enrichment complete" message
# - Events with dst_ip only are now accepted
```

### Validation
1. Verify file uploads complete in ~5s
2. Verify incidents are still generated
3. Verify reports are still created
4. Verify no errors in logs
5. Verify dst_ip-only logs are processed

## Rollback Plan

If issues arise:
1. Restore `main.py` from git
2. Restore `shared_models/events.py` from git
3. Restore `normalization/service.py` from git
4. Restore `core/config.py` from git
5. Restore `.env` from git

All changes are reversible via git.

## Timeline

- **Phase 1 (Remove GeoIP)**: 5 minutes
- **Phase 2 (Improve Validation)**: 10 minutes
- **Phase 3 (Cleanup)**: 5 minutes
- **Testing**: 10 minutes
- **Total**: ~30 minutes

## Success Criteria

✅ File uploads complete in ~5s (was 95s)
✅ No GeoIP-related log messages
✅ Logs with dst_ip only are processed
✅ Incidents still generated correctly
✅ Reports still created
✅ No errors in logs
✅ Memory usage reduced by ~80MB
