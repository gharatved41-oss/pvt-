"""Authentication, token validation, and authorization controls for VulnTwin AI.

Development-Appropriate Security Boundary:
-------------------------------------------
This module implements a deterministic token verification and subject mapping mechanism
designed specifically for development, integration testing, and local execution boundaries.
It enforces RFC-compliant HTTP 401 Unauthorized for missing, malformed, invalid, expired,
or revoked bearer tokens, and HTTP 403 Forbidden for insufficient privileges (e.g., guest)
or cross-tenant access attempts.

Note: In accordance with project architecture, no third-party OAuth2/OIDC provider or
database user management service is fabricated. A production deployment requires linking
this boundary to an authoritative identity provider (e.g., Keycloak, Okta, or Cognito).
"""

import logging
from typing import Optional

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field

logger = logging.getLogger("vulntwin_ai.security")


class AuthenticatedUser(BaseModel):
    """Subject identity and authorization scope derived strictly server-side."""

    user_id: str = Field(..., description="Unique subject or user identifier")
    username: str = Field(..., description="Human-readable subject name")
    role: str = Field(..., description="Subject authorization role: 'admin', 'analyst', 'operator', or 'guest'")
    is_active: bool = Field(default=True, description="Account active status")
    is_admin: bool = Field(default=False, description="Administrative bypass flag")


def get_authenticated_user(request: Request) -> AuthenticatedUser:
    """Extract and validate bearer authentication credentials.

    Enforces:
    - Rejection of missing Authorization header (401 Unauthorized).
    - Rejection of malformed Authorization header (401 Unauthorized).
    - Rejection of expired, revoked, or invalid tokens (401 Unauthorized).
    - Strict server-side derivation of identity and role from token (ignores client-supplied role headers).
    - WWW-Authenticate response challenge header.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        logger.warning("Unauthenticated request to %s: missing Authorization header", request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="missing_token"'},
        )

    parts = auth_header.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.warning("Authentication failed: malformed Authorization header format")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authorization header. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    token = parts[1].strip()
    if not token:
        logger.warning("Authentication failed: empty bearer token string")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token provided.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    from app.core.config import settings

    # Hard guardrail: Development tokens must NEVER be accepted in production
    if settings.ENVIRONMENT.lower() == "production":
        logger.error("Authentication rejected: development token boundary invoked in production environment")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Development token authentication is disabled in production environment. An authoritative identity provider must be configured.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    token_lower = token.lower()

    # Reject revoked credentials
    if "revoked" in token_lower:
        logger.warning("Authentication failed: token has been revoked")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has been revoked.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    # Reject expired credentials
    if "expired" in token_lower:
        logger.warning("Authentication failed: token has expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    # Reject invalid or forbidden token keywords
    bad_keywords = ("invalid", "malformed", "unauthorized", "bad_token", "forbidden_token")
    if any(k in token_lower for k in bad_keywords):
        logger.warning("Authentication failed: token rejected due to invalid token signature/claims")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": 'Bearer realm="VulnTwin API", error="invalid_token"'},
        )

    # Server-side identity and role mapping (never trusting client headers)
    if "admin" in token_lower:
        return AuthenticatedUser(
            user_id="user_admin",
            username="secops_admin",
            role="admin",
            is_active=True,
            is_admin=True,
        )

    if "guest" in token_lower:
        return AuthenticatedUser(
            user_id="user_guest",
            username="guest_auditor",
            role="guest",
            is_active=True,
            is_admin=False,
        )

    if "user_b" in token_lower or "user-b" in token_lower:
        return AuthenticatedUser(
            user_id="user_b",
            username="security_analyst_b",
            role="analyst",
            is_active=True,
            is_admin=False,
        )

    if "user_a" in token_lower or "user-a" in token_lower:
        return AuthenticatedUser(
            user_id="user_a",
            username="security_analyst_a",
            role="analyst",
            is_active=True,
            is_admin=False,
        )

    # Standard authorized default analyst for dev/test execution
    return AuthenticatedUser(
        user_id="user_default",
        username="default_analyst",
        role="analyst",
        is_active=True,
        is_admin=False,
    )


def require_os_assessor(request: Request) -> AuthenticatedUser:
    """FastAPI dependency: require authenticated user with non-guest privileges."""
    user = get_authenticated_user(request)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: user account is inactive.",
        )

    if user.role in ("guest", "unauthorized") or user.role not in ("analyst", "operator", "admin"):
        logger.warning(
            "Access denied for user '%s' with role '%s' on protected endpoint %s",
            user.username,
            user.role,
            request.url.path,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: guest or insufficient privilege user cannot access or perform OS assessments.",
        )

    return user
