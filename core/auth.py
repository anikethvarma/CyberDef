"""
Authentication utilities for API access control.

Implements lightweight HMAC-signed bearer tokens using only stdlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import get_settings

_bearer_scheme = HTTPBearer(auto_error=False)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _sign(payload_b64: str, secret_key: str) -> str:
    digest = hmac.new(
        secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return _b64url_encode(digest)


def create_access_token(username: str) -> tuple[str, int]:
    """Create signed access token and return it with TTL in seconds."""
    settings = get_settings()
    expires_in_seconds = settings.auth_token_ttl_minutes * 60
    payload = {
        "sub": username,
        "exp": int(time.time()) + expires_in_seconds,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)
    signature = _sign(payload_b64, settings.auth_secret_key)
    return f"{payload_b64}.{signature}", expires_in_seconds


def verify_access_token(token: str) -> str | None:
    """Return username from token if valid and unexpired; otherwise None."""
    settings = get_settings()
    try:
        payload_b64, signature = token.split(".", 1)
    except ValueError:
        return None

    expected_signature = _sign(payload_b64, settings.auth_secret_key)
    if not secrets.compare_digest(signature, expected_signature):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None

    username = payload.get("sub")
    expires_at = payload.get("exp")

    if not isinstance(username, str) or not isinstance(expires_at, int):
        return None
    if int(time.time()) >= expires_at:
        return None
    return username


def verify_user_credentials(username: str, password: str) -> bool:
    """
    Validate submitted credentials.

    Primary mode:
    - Username format: "<prefix><emp_id>" (default prefix: "soc.")
    - emp_id must exist in configured AUTH_EMP_IDS.
    - Password must match AUTH_COMMON_PASSWORD.

    Fallback mode:
    - If AUTH_EMP_IDS is empty, legacy AUTH_USERNAME/AUTH_PASSWORD is used.
    """
    settings = get_settings()
    configured_emp_ids = [
        emp_id.strip()
        for emp_id in settings.auth_emp_ids.split(",")
        if emp_id and emp_id.strip()
    ]

    # Primary multi-user mode: soc.<emp_id>
    if configured_emp_ids:
        if not secrets.compare_digest(password, settings.auth_common_password):
            return False

        prefix = settings.auth_username_prefix or "soc."
        if not username.startswith(prefix):
            return False

        emp_id = username[len(prefix):].strip()
        if not emp_id:
            return False

        return any(secrets.compare_digest(emp_id, allowed_id) for allowed_id in configured_emp_ids)

    # Fallback legacy mode
    return (
        secrets.compare_digest(username, settings.auth_username)
        and secrets.compare_digest(password, settings.auth_password)
    )


def _extract_emp_id(username: str) -> str | None:
    """Extract employee id from configured username format."""
    settings = get_settings()
    prefix = settings.auth_username_prefix or "soc."
    if not username.startswith(prefix):
        return None
    emp_id = username[len(prefix):].strip()
    return emp_id or None


def _parse_emp_name_map(raw_map: str) -> dict[str, str]:
    """Parse comma-separated emp_id:name pairs from env."""
    mapping: dict[str, str] = {}
    if not raw_map:
        return mapping

    for item in raw_map.split(","):
        pair = item.strip()
        if not pair:
            continue
        if ":" in pair:
            emp_id, name = pair.split(":", 1)
        elif "=" in pair:
            emp_id, name = pair.split("=", 1)
        else:
            continue

        emp_id = emp_id.strip()
        name = name.strip()
        if emp_id and name:
            mapping[emp_id] = name

    return mapping


def resolve_user_identity(username: str) -> dict[str, str | None]:
    """
    Resolve identity details for UI display.

    Returns:
    - username: original login username
    - emp_id: extracted employee id when username matches prefix format
    - name: mapped display name (or a safe fallback)
    """
    settings = get_settings()
    emp_id = _extract_emp_id(username)
    name_map = _parse_emp_name_map(settings.auth_emp_name_map)

    if emp_id and emp_id in name_map:
        display_name = name_map[emp_id]
    elif emp_id:
        display_name = f"SOC {emp_id}"
    else:
        display_name = username

    return {
        "username": username,
        "emp_id": emp_id,
        "name": display_name,
    }


def _get_token_from_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None,
) -> str | None:
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials
    query_token = request.query_params.get("access_token")
    if query_token:
        return query_token
    return None


def unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    """Dependency for protecting endpoints with bearer auth."""
    token = _get_token_from_request(request, credentials)
    if not token:
        raise unauthorized()

    username = verify_access_token(token)
    if not username:
        raise unauthorized(detail="Invalid or expired token")

    return username


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
