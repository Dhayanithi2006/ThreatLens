"""
ThreatLens - Application Security & Authentication Utilities
Role-based administrative authorization, API key validation, and actor resolution.
"""

import hmac
from typing import Optional
from fastapi import Header, HTTPException, status
from backend.core import config


def extract_api_key(
    x_api_key: Optional[str] = None,
    authorization: Optional[str] = None
) -> Optional[str]:
    """Extracts API key from X-API-Key header or Bearer authorization token."""
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    if authorization and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1:
            return parts[0]
    return None


def verify_admin_access(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """
    Validates administrative authorization for mutating operations,
    governance policy updates, and manual graph ingestion.

    Returns the identified actor identifier for audit ledger recording.
    """
    provided_key = extract_api_key(x_api_key, authorization)

    if config.REQUIRE_API_KEY:
        if not provided_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: X-API-Key or Bearer token required for administrative operation.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(provided_key, config.ADMIN_API_KEY):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid administrative credentials.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return "admin-api-key"

    # Development fallback mode
    if provided_key:
        if hmac.compare_digest(provided_key, config.ADMIN_API_KEY):
            return "admin-api-key"
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid administrative credentials.",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    return "dev-user-local"


def get_actor_identity(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """Non-blocking actor resolution for read-only audit attribution."""
    provided_key = extract_api_key(x_api_key, authorization)
    if provided_key and hmac.compare_digest(provided_key, config.ADMIN_API_KEY):
        return "admin-api-key"
    return "analyst-session"
