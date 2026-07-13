"""Native authentication API: register, sign in (password / Google), whoami.

These endpoints are unauthenticated by nature, so they carry their own
fixed-window per-IP rate limit (10/min) to blunt credential stuffing and
registration abuse. Successful auth returns a short-lived HS256 session token
consumed by the same RBAC pipeline as Keycloak tokens. Sign-out is client-side
token disposal (the API is stateless).
"""
from __future__ import annotations

import threading
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps import get_principal
from app.core.accounts import (
    RegistrationError,
    UserAccount,
    build_user_store,
    hash_password,
    issue_session_token,
    sign_in_with_google,
    validate_registration,
    verify_password,
)
from app.core.authz import permissions_for
from app.core.config import settings
from app.core.exceptions import AuthError
from app.core.logging import get_logger
from app.core.security import Principal

router = APIRouter()
log = get_logger("api.auth")

_RATE_LIMIT = 10  # requests / window / ip
_WINDOW_SECONDS = 60.0
_hits: dict[str, list[float]] = {}
_hits_lock = threading.Lock()


def _throttle(request: Request) -> None:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _hits_lock:
        window = _hits.setdefault(ip, [])
        window[:] = [t for t in window if t > now - _WINDOW_SECONDS]
        if len(window) >= _RATE_LIMIT:
            raise HTTPException(status_code=429, detail="too many auth attempts")
        window.append(now)


class RegisterRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)
    display_name: str = Field(default="", max_length=256)


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


class GoogleSignInRequest(BaseModel):
    credential: str = Field(max_length=8192, description="Google ID token (JWT)")


class SessionResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int
    email: str
    display_name: str
    tenant: str
    roles: list[str]


def _session(user: UserAccount) -> SessionResponse:
    token, ttl = issue_session_token(user)
    return SessionResponse(
        access_token=token, expires_in=ttl, email=user.email,
        display_name=user.display_name, tenant=user.tenant,
        roles=list(user.roles),
    )


@router.post("/register", response_model=SessionResponse, status_code=201)
async def register(body: RegisterRequest, request: Request) -> SessionResponse:
    _throttle(request)
    if not settings.allow_self_registration:
        raise HTTPException(status_code=403, detail="self-registration is disabled")
    try:
        validate_registration(body.email, body.password)
        user = build_user_store().create(UserAccount(
            subject=str(uuid.uuid4()),
            email=body.email.lower(),
            display_name=body.display_name or body.email.split("@")[0],
            tenant=settings.default_tenant,
            roles=(settings.default_user_role,),
            provider="password",
            password_hash=hash_password(body.password),
        ))
    except RegistrationError as exc:
        status = 409 if "already exists" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    return _session(user)


@router.post("/login", response_model=SessionResponse)
async def login(body: LoginRequest, request: Request) -> SessionResponse:
    _throttle(request)
    user = build_user_store().get_by_email(body.email)
    # Uniform error for unknown email vs wrong password (no account probing).
    if (user is None or user.provider != "password"
            or not verify_password(body.password, user.password_hash)):
        log.warning("login_failed", email=body.email)
        raise HTTPException(status_code=401, detail="invalid email or password")
    log.info("login_succeeded", email=user.email, tenant=user.tenant)
    return _session(user)


@router.post("/google", response_model=SessionResponse)
async def google_sign_in(body: GoogleSignInRequest, request: Request) -> SessionResponse:
    _throttle(request)
    if not settings.google_client_id:
        raise HTTPException(
            status_code=503,
            detail="Google sign-in is not configured; set AEGIS_GOOGLE_CLIENT_ID")
    try:
        user, token, ttl = sign_in_with_google(body.credential)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return SessionResponse(
        access_token=token, expires_in=ttl, email=user.email,
        display_name=user.display_name, tenant=user.tenant,
        roles=list(user.roles),
    )


class WhoAmI(BaseModel):
    subject: str
    username: str
    tenant: str
    roles: list[str]
    permissions: list[str]


@router.get("/me", response_model=WhoAmI)
async def whoami(principal: Principal = Depends(get_principal)) -> WhoAmI:
    return WhoAmI(
        subject=principal.subject,
        username=principal.username,
        tenant=principal.tenant,
        roles=sorted(principal.roles),
        permissions=sorted(p.value for p in permissions_for(principal)),
    )
