"""
PhishGuard-AI — Security & Authentication Module.
===================================================

Implements two authentication dependencies:

``verify_api_key``
    Bearer-token check for the analysis API used by the browser extension.

``verify_dashboard_access``
    Protects every ``/api/v1/dashboard`` route.  Accepts either the
    administrative bearer token (API clients, tests) or a server-side
    browser session created by ``POST /api/v1/dashboard/auth/login`` and
    carried in an ``HttpOnly``, ``SameSite=Strict`` cookie.  The cookie path
    exists because ``EventSource`` streams and ``<a download>`` links cannot
    attach an ``Authorization`` header.

Architecture Layer : Cross-Cutting / Middleware
Security Model    : Static Bearer Token + opaque server-side session
Thesis Reference  : §4.3 — API Gateway Security Controls
"""

from __future__ import annotations

import hmac
import secrets
import time
from typing import Final, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.config import ADMIN_API_TOKEN, API_SECRET_TOKEN, DASHBOARD_SESSION_TTL_SECONDS

# ---------------------------------------------------------------------------
# HTTP Bearer scheme — FastAPI will extract the token from the
# ``Authorization: Bearer <token>`` header automatically and surface it as
# an ``HTTPAuthorizationCredentials`` instance.
# ---------------------------------------------------------------------------
_bearer_scheme: Final[HTTPBearer] = HTTPBearer(
    scheme_name="PhishGuard API Key",
    description="Provide your PhishGuard API key as a Bearer token.",
    auto_error=True,  # Rejects the request if the header is missing entirely.
)


async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency that validates the incoming bearer token.

    Designed for injection via ``Depends(verify_api_key)`` on any router
    or individual endpoint that requires authentication.

    Uses ``hmac.compare_digest()`` to perform a constant-time comparison,
    mitigating timing side-channel attacks that could leak the secret
    length or character positions.

    Parameters
    ----------
    credentials : HTTPAuthorizationCredentials
        Automatically populated by the ``HTTPBearer`` scheme from the
        ``Authorization`` header.

    Returns
    -------
    str
        The validated API key (useful for downstream audit logging).

    Raises
    ------
    HTTPException (401)
        If the token does not match the configured secret.
    """
    # ── Constant-time comparison to prevent timing side-channel attacks ──
    if not hmac.compare_digest(credentials.credentials, API_SECRET_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_API_KEY",
                "message": (
                    "The provided bearer token is invalid or has been "
                    "revoked.  Contact your PhishGuard administrator."
                ),
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials


# ==============================================================================
# Dashboard (administrative) access control
# ==============================================================================

SESSION_COOKIE_NAME: Final[str] = "phishguard_session"

# session id -> expiry (monotonic seconds).  In-memory by design: sessions are
# invalidated on restart, and a single-process deployment needs no shared store.
_SESSIONS: Final[dict[str, float]] = {}

_optional_bearer: Final[HTTPBearer] = HTTPBearer(
    scheme_name="PhishGuard Admin Key",
    description="Administrative key for SOC dashboard endpoints.",
    auto_error=False,
)


def is_valid_admin_key(candidate: str) -> bool:
    """Constant-time comparison of ``candidate`` against the admin key."""
    return hmac.compare_digest(candidate.encode("utf-8"), ADMIN_API_TOKEN.encode("utf-8"))


def create_dashboard_session() -> str:
    """Create a new opaque session identifier and return it."""
    now = time.monotonic()
    for sid in [sid for sid, expiry in _SESSIONS.items() if expiry <= now]:
        _SESSIONS.pop(sid, None)
    session_id = secrets.token_urlsafe(32)
    _SESSIONS[session_id] = now + DASHBOARD_SESSION_TTL_SECONDS
    return session_id


def destroy_dashboard_session(session_id: Optional[str]) -> None:
    """Invalidate ``session_id`` (no-op if unknown)."""
    if session_id:
        _SESSIONS.pop(session_id, None)


def is_valid_dashboard_session(session_id: Optional[str]) -> bool:
    """True if ``session_id`` exists and has not expired."""
    if not session_id:
        return False
    expiry = _SESSIONS.get(session_id)
    if expiry is None:
        return False
    if expiry <= time.monotonic():
        _SESSIONS.pop(session_id, None)
        return False
    return True


async def verify_dashboard_access(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_optional_bearer),
) -> str:
    """Authorise a request to an administrative dashboard route.

    Returns ``"bearer"`` or ``"session"`` (the mechanism that authorised the
    request).  Raises HTTP 401 otherwise.  The login / session-probe / logout
    routes are exempt so an unauthenticated browser can sign in.
    """
    if request.url.path.startswith("/api/v1/dashboard/auth/"):
        return "public"

    if credentials is not None and is_valid_admin_key(credentials.credentials):
        return "bearer"

    if is_valid_dashboard_session(request.cookies.get(SESSION_COOKIE_NAME)):
        return "session"

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "DASHBOARD_AUTH_REQUIRED",
            "message": "Administrative authentication is required for SOC dashboard endpoints.",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )
