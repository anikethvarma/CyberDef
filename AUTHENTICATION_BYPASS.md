# Authentication Bypass for Backend Testing

## Date: April 1, 2026

## Overview

Authentication has been made optional for key endpoints to enable backend testing without requiring login/UI interaction. This allows direct API testing via tools like curl, Postman, or Python scripts.

## Changes Made

### 1. Added Optional Authentication Dependency

**File**: `core/auth.py`

Added a new `optional_auth` dependency that:
- Returns the authenticated username if a valid token is provided
- Returns a default test user (`backend_test_user`) if no token is provided
- Returns a default test user if an invalid token is provided

```python
async def optional_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    """
    Optional authentication dependency for backend testing.
    
    Returns authenticated username if token is provided and valid,
    otherwise returns a default test user for backend testing without login.
    """
    token = _get_token_from_request(request, credentials)
    if not token:
        # No token provided - return default test user for backend testing
        return "backend_test_user"

    username = verify_access_token(token)
    if not username:
        # Invalid token - return default test user for backend testing
        return "backend_test_user"

    return username
```

### 2. Updated Endpoints to Use Optional Authentication

**File**: `main.py`

Updated the following endpoints to use `optional_auth` instead of `require_auth`:

1. **POST /api/v1/analyze** - Main analysis endpoint
2. **GET /api/v1/threat-summary/today** - Threat summary endpoint
3. **GET /api/v1/agent-outputs/{file_id}** - Agent outputs endpoint
4. **GET /api/v1/rollups** - Rollup analysis endpoint
5. **GET /api/v1/validation** - Validation stats endpoint
6. **DELETE /api/v1/system/clear-all** - System clear endpoint

**File**: `file_intake/routes.py`

Updated the following endpoint:
- **GET /api/v1/files/{file_id}/incidents-json** - Incident JSON report download

### 3. File Upload Already Bypassed

The file upload endpoint was already accessible without authentication:
- **POST /api/v1/files/upload** - File upload endpoint (no auth required)

## Usage Examples

### 1. Upload a File (No Authentication Required)

```bash
curl -X POST "http://localhost:8000/api/v1/files/upload" \
  -F "file=@/path/to/logfile.csv" \
  -F "description=Test upload"
```

Response:
```json
{
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "logfile.csv",
  "status": "uploaded",
  "message": "File uploaded successfully"
}
```

### 2. Analyze a File (No Authentication Required)

```bash
curl -X POST "http://localhost:8000/api/v1/analyze?file_id=550e8400-e29b-41d4-a716-446655440000"
```

Response:
```json
{
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "events_parsed": 1000,
  "events_normalized": 950,
  "tier1_deterministic": {
    "threats_found": 5,
    "matches": 25,
    "processing_time_ms": 150
  },
  "tier2_correlation": {
    "findings": 2,
    "new_patterns": 1,
    "processing_time_ms": 50
  },
  "tier3_ai": {
    "chunks_analyzed": 3,
    "incidents_created": 2
  }
}
```

### 3. Download Incident JSON Report (No Authentication Required)

```bash
curl -X GET "http://localhost:8000/api/v1/files/550e8400-e29b-41d4-a716-446655440000/incidents-json" \
  -o incidents.json
```

### 4. Get Threat Summary (No Authentication Required)

```bash
curl -X GET "http://localhost:8000/api/v1/threat-summary/today"
```

### 5. Using with Authentication (Optional)

If you want to test with authentication, you can still provide a token:

```bash
# Login first
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=soc.133745&password=admin123"

# Response includes access_token
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 28800
}

# Use token in subsequent requests
curl -X POST "http://localhost:8000/api/v1/analyze?file_id=550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer eyJhbGc..."
```

## Python Script Example

```python
import requests

# Base URL
BASE_URL = "http://localhost:8000/api/v1"

# 1. Upload file
with open("logfile.csv", "rb") as f:
    files = {"file": f}
    data = {"description": "Test upload"}
    response = requests.post(f"{BASE_URL}/files/upload", files=files, data=data)
    file_id = response.json()["file_id"]
    print(f"File uploaded: {file_id}")

# 2. Analyze file
response = requests.post(f"{BASE_URL}/analyze", params={"file_id": file_id})
result = response.json()
print(f"Analysis complete: {result['tier1_deterministic']['threats_found']} threats found")

# 3. Download incident JSON
response = requests.get(f"{BASE_URL}/files/{file_id}/incidents-json")
with open("incidents.json", "wb") as f:
    f.write(response.content)
print("Incident report downloaded")
```

## Important Notes

### Security Considerations

1. **Production Deployment**: In production, you should:
   - Remove or disable `optional_auth` 
   - Use `require_auth` for all sensitive endpoints
   - Implement proper API key or OAuth authentication

2. **Default Test User**: The `backend_test_user` is used when no authentication is provided:
   - This user has no real emp_id (will be `None` in reports)
   - JSON reports will have `emp_id: null` when using the test user

3. **Network Security**: Ensure the backend is only accessible from trusted networks during testing

### Endpoints Still Requiring Authentication

The following endpoints still require authentication (using `require_auth`):
- **Case API endpoints** (`/api/v1/cases/*`) - Protected at router level
- **Auth endpoints** (`/api/v1/auth/me`, `/api/v1/auth/logout`) - Require valid token

### Reverting to Full Authentication

To revert to full authentication, simply change all `optional_auth` back to `require_auth` in:
- `main.py` (6 endpoints)
- `file_intake/routes.py` (1 endpoint)

## Testing Workflow

### Complete Backend Test Flow

```bash
# 1. Upload file
FILE_ID=$(curl -s -X POST "http://localhost:8000/api/v1/files/upload" \
  -F "file=@test.csv" | jq -r '.file_id')

echo "File ID: $FILE_ID"

# 2. Analyze file
curl -X POST "http://localhost:8000/api/v1/analyze?file_id=$FILE_ID"

# 3. Get incidents JSON
curl -X GET "http://localhost:8000/api/v1/files/$FILE_ID/incidents-json" \
  -o "incidents_$FILE_ID.json"

# 4. Get threat summary
curl -X GET "http://localhost:8000/api/v1/threat-summary/today"

# 5. Get agent outputs
curl -X GET "http://localhost:8000/api/v1/agent-outputs/$FILE_ID"

echo "Testing complete!"
```

## Files Modified

1. `core/auth.py` - Added `optional_auth` dependency
2. `main.py` - Updated 6 endpoints to use `optional_auth`
3. `file_intake/routes.py` - Updated 1 endpoint to use `optional_auth`

## Summary

✅ File upload: No authentication required (already)
✅ File analysis: Authentication optional (bypassed for testing)
✅ Incident reports: Authentication optional (bypassed for testing)
✅ Threat summary: Authentication optional (bypassed for testing)
✅ Agent outputs: Authentication optional (bypassed for testing)
✅ System endpoints: Authentication optional (bypassed for testing)

Backend testing can now be performed without login/UI interaction while maintaining the ability to use authentication when needed.
