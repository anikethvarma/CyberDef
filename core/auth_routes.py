"""
Authentication routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from core.auth import (
    create_access_token,
    require_auth,
    resolve_user_identity,
    verify_user_credentials,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


from typing import Optional

class UserIdentityResponse(BaseModel):
    username: str
    emp_id: Optional[str] = None
    name: str


class LoginResponse(UserIdentityResponse):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Sign in",
    description="Authenticate with username and password to obtain a bearer token.",
)
async def login(payload: LoginRequest) -> LoginResponse:
    if not verify_user_credentials(payload.username, payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_access_token(payload.username)
    identity = resolve_user_identity(payload.username)
    return LoginResponse(
        access_token=token,
        expires_in=expires_in,
        username=identity["username"],
        emp_id=identity["emp_id"],
        name=identity["name"] or identity["username"],
    )


@router.get(
    "/me",
    response_model=UserIdentityResponse,
    summary="Current user",
    description="Validate the current bearer token and return identity info.",
)
async def me(current_user: str = Depends(require_auth)) -> UserIdentityResponse:
    identity = resolve_user_identity(current_user)
    return UserIdentityResponse(
        username=identity["username"],
        emp_id=identity["emp_id"],
        name=identity["name"] or identity["username"],
    )


@router.post(
    "/logout",
    summary="Sign out",
    description="Client-side logout endpoint for consistent auth flow.",
)
async def logout(_: str = Depends(require_auth)) -> dict[str, str]:
    # Stateless token model: client removes token locally.
    return {"message": "Logged out"}
