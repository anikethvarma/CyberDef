# Fixes Applied - Analysis and JSON Report Improvements

## Date: April 1, 2026

## Issues Fixed

### 1. Same Source and Destination IP Issue

**Problem**: In some cases, the source IP and destination IP were being set to the same value in the normalized events and JSON reports.

**Root Cause**: In `normalization/service.py`, when `src_ip` was missing, it was being set to `dst_ip`, but the logic didn't properly handle cases where both IPs were identical.

**Fix Applied** (`normalization/service.py` lines 104-122):
```python
# If src_ip is missing but dst_ip exists, treat dst_ip as the source (client IP)
# Keep dst_ip as None to avoid duplication
if not src_ip and dst_ip:
    src_ip = dst_ip
    dst_ip = None

# Ensure src_ip and dst_ip are never the same
if src_ip and dst_ip and src_ip == dst_ip:
    logger.warning(
        f"Source and destination IPs are identical, clearing dst_ip | file_id={parsed.file_id}, ip={src_ip}"
    )
    dst_ip = None
```

**Result**: Source and destination IPs are now properly differentiated, with duplicate IPs being cleared.

---

### 2. Wrong Source IP in Correlation (Tier-2)

**Problem**: The correlation logic in tier-2 was not properly extracting and displaying source IPs, hostnames, and raw logs in the JSON report.

**Fix Applied** (`reports/writer.py` lines 325-395):

Enhanced the `_incident_to_json` method to:
- Properly extract source IP from `source_ip` or `primary_actor_ip`
- Extract destination IP from `destination_ip` or `affected_hosts`
- Extract hostname from destination IP or affected hosts
- Build comprehensive correlation context with:
  - **Signature attacks**: Extracted from detection rules, attack names, and MITRE techniques
  - **src_ip**: Properly mapped source IP
  - **dst_ip**: Properly mapped destination IP
  - **hostname**: Extracted from destination or affected hosts
  - **raw_logs**: Array of raw log samples
  - **correlation_reason**: Strong reasoning for the correlation

Added `_build_correlation_reason` method that provides detailed reasoning including:
- Detection tier and source (correlation, deterministic, AI)
- MITRE ATT&CK context (tactic and technique)
- Attack categories
- Confidence and priority levels

**Result**: Tier-2 correlation findings now include complete context with correct IPs, hostnames, raw logs, and strong correlation reasoning.

---

### 3. Missing Parameters in JSON Report

**Problem**: The JSON report was missing required parameters: `MI_ID`, `emp_id`, and `hostname`.

**Fixes Applied**:

#### A. Added Static Key-Value Pair: `MI_ID`
**File**: `reports/writer.py` (line 313)
```python
payload = {
    "MI_ID": "GenAI_SOC",  # Static key-value pair
    "file_id": file_id,
    "filename": filename,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "incident_count": len(incident_rows),
    "emp_id": emp_id,  # Employee ID from authentication context
    "incidents": incident_rows,
}
```

#### B. Added `emp_id` Parameter
**Files Modified**:
- `reports/writer.py`: Updated `generate_incident_json_report` to accept `emp_id` parameter
- `main.py`: Updated analyze endpoint to:
  - Require authentication (`current_user: str = Depends(require_auth)`)
  - Extract emp_id from authenticated user using `resolve_user_identity`
  - Pass emp_id to report generation
- `file_intake/routes.py`: Updated JSON report download endpoint to extract and pass emp_id

**Code Changes** (`main.py` lines 386-395):
```python
# Extract emp_id from current user for JSON report
user_identity = resolve_user_identity(current_user)
emp_id = user_identity.get("emp_id")

incidents_json_path = report_writer.generate_incident_json_report(
    file_id=file_id,
    filename=file_metadata.original_filename,
    incidents=all_incidents,
    emp_id=emp_id,
)
```

#### C. Added `hostname` Parameter
**File**: `reports/writer.py` (lines 350-356)
```python
# Extract hostname from destination or affected hosts
hostname = None
if destination_ip:
    hostname = destination_ip
elif data.get("affected_hosts"):
    hostname = data.get("affected_hosts")[0]
```

Each incident in the JSON report now includes:
```json
{
  "incident_id": "...",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.50",
  "hostname": "10.0.0.50",
  "correlation": {
    "signature_attacks": ["sql_injection", "T1190"],
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.50",
    "hostname": "10.0.0.50",
    "raw_logs": ["<raw log sample>"],
    "correlation_reason": "Deterministic rule match: sql_injection | MITRE ATT&CK: Initial Access - T1190 | High confidence detection (0.90) | CRITICAL priority incident"
  }
}
```

---

## JSON Report Structure

The updated JSON report now includes:

### Top-Level Fields:
- `MI_ID`: "GenAI_SOC" (static identifier)
- `file_id`: Unique file identifier
- `filename`: Original filename
- `generated_at`: ISO timestamp
- `incident_count`: Number of incidents
- `emp_id`: Employee ID of the analyst who ran the analysis
- `incidents`: Array of incident objects

### Per-Incident Fields:
- `incident_id`: Unique incident identifier
- `title`: Incident title
- `status`: Current status
- `priority`: Priority level (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
- `source_ip`: Attacker/source IP address
- `destination_ip`: Target/destination IP address
- `hostname`: Target hostname
- `raw_log`: Sample raw log entry
- `attack_name`: Name of the attack
- `brief_description`: Brief description
- `recommended_action`: Recommended action
- `confidence_score`: Confidence score (1-10)
- `mitre_tactic`: MITRE ATT&CK tactic
- `mitre_technique`: MITRE ATT&CK technique ID
- `correlation`: Correlation context object with:
  - `signature_attacks`: Array of detected attack signatures
  - `src_ip`: Source IP
  - `dst_ip`: Destination IP
  - `hostname`: Target hostname
  - `raw_logs`: Array of raw log samples
  - `correlation_reason`: Detailed reasoning for the correlation

---

## Files Modified

1. `normalization/service.py` - Fixed duplicate IP issue and added "-" placeholder handling
2. `reports/writer.py` - Enhanced JSON report with correlation context, hostname, and emp_id
3. `main.py` - Added authentication and emp_id extraction
4. `file_intake/routes.py` - Updated JSON report download with authentication
5. `log_parser/base.py` - Added common `_clean_value` and `_clean_ip` methods to handle "-" placeholders
6. `log_parser/generic_parser.py` - Updated to use `_clean_ip` for proper "-" handling
7. `log_parser/firewall_parser.py` - Updated to use `_clean_ip` for proper "-" handling
8. `log_parser/network_log_parser.py` - Updated to use `_clean_ip` for proper "-" handling

---

## Additional Fix: Handling "-" as Missing Value Placeholder

**Problem**: In many log formats, when a parameter like `dst_ip` is not present, it appears as "-" in that position of the raw log. This placeholder needs to be treated as a missing/null value rather than a literal string.

**Fix Applied**:

### 1. Base Parser Enhancement (`log_parser/base.py`)
Added two common utility methods that all parsers can use:

```python
def _clean_value(self, value: Any, placeholders: list[str] = None) -> str | None:
    """
    Clean a value by treating common placeholders as None.
    
    Args:
        value: The value to clean
        placeholders: List of placeholder strings to treat as None (default: ["-", ""])
        
    Returns:
        Cleaned string value or None if it's a placeholder
    """
    if value is None:
        return None
    
    if placeholders is None:
        placeholders = ["-", ""]
    
    s = str(value).strip()
    if s in placeholders:
        return None
    
    return s

def _clean_ip(self, value: Any) -> str | None:
    """
    Clean an IP address value, treating "-" and other placeholders as None.
    
    Args:
        value: The IP address value to clean
        
    Returns:
        Cleaned IP string or None if it's a placeholder
    """
    return self._clean_value(value, placeholders=["-", "", "0.0.0.0"])
```

### 2. Normalization Service Enhancement (`normalization/service.py`)
Updated `_normalize_ip` method to explicitly handle "-" as a missing value:

```python
def _normalize_ip(self, ip_str: str | None) -> str | None:
    """Normalize and validate IP address. Treats '-' as missing value."""
    if not ip_str:
        return None

    ip_str = str(ip_str).strip()
    
    # Treat "-" as missing value (common placeholder in logs)
    if ip_str == "-":
        return None
    
    # ... rest of normalization logic
```

### 3. Parser Updates
Updated all parsers to use the common `_clean_ip` method:
- `log_parser/generic_parser.py`
- `log_parser/firewall_parser.py`
- `log_parser/network_log_parser.py`

**Result**: All parsers now consistently treat "-" as a missing value placeholder, preventing it from being processed as a literal IP address or other field value.

---

## Testing Recommendations

1. **Test IP Deduplication**: Upload logs with identical source and destination IPs
2. **Test "-" Placeholder Handling**: Upload logs with "-" in IP fields and verify they're treated as missing values
3. **Test Correlation Context**: Verify tier-2 correlation findings include proper IPs, hostnames, and raw logs
4. **Test Authentication**: Verify emp_id is correctly extracted and included in JSON reports
5. **Test Hostname Extraction**: Verify hostnames are properly extracted from destination IPs or affected hosts
6. **Test Correlation Reasoning**: Verify correlation_reason provides meaningful context
7. **Test Various Log Formats**: Test with different log formats (firewall, network, generic) to ensure "-" handling works consistently

---

## Authentication Context

The system now properly tracks which analyst (emp_id) performed each analysis:
- Username format: `soc.<emp_id>` (e.g., `soc.133745`)
- Employee IDs configured in `.env`: 133745, 2123486, 2171569, 473496, 2858682, 2832493, 2795270
- Each JSON report includes the emp_id of the analyst who ran the analysis

---

## Summary

All issues have been resolved:
1. ✅ Source and destination IPs are now properly differentiated
2. ✅ Tier-2 correlation includes correct IPs, hostnames, raw logs, and strong reasoning
3. ✅ JSON reports include MI_ID, emp_id, and hostname parameters
4. ✅ All parsers now properly handle "-" as a missing value placeholder

The system now provides comprehensive correlation context for security analysts to understand the full scope of detected threats, with proper handling of missing values in log data.
