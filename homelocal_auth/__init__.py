"""
homelocal-auth: Reusable JWT authentication for Home.Local FastAPI services.

This library provides:
- JWKS-based JWT validation with TTL caching
- FastAPI dependency factories for role-based access control
- Pluggable user resolution (not coupled to SQLAlchemy)

Quick start:
    from homelocal_auth import AuthConfig, require_developer, require_admin

    config = AuthConfig(jwks_url="https://auth.example.com/.well-known/jwks.json")

    @app.get("/api/apps")
    async def list_apps(claims: TokenClaims = Depends(require_developer(config))):
        return {"user_id": claims.sub}
"""

from homelocal_auth.claims import TokenClaims
from homelocal_auth.config import AuthConfig
from homelocal_auth.core import AuthenticationError, verify_bearer_token
from homelocal_auth.fastapi import (
    optional_claims,
    require_admin,
    require_any_role,
    require_business_with_status,
    require_claim,
    require_claims,
    require_developer,
    require_role,
)
from homelocal_auth.jwks import JWKSClient
from homelocal_auth.resolvers import UserResolver, UserResolverFunc

__version__ = "0.2.0"

__all__ = [
    # Config
    "AuthConfig",
    # Claims
    "TokenClaims",
    # Core
    "verify_bearer_token",
    "AuthenticationError",
    # JWKS
    "JWKSClient",
    # FastAPI dependencies
    "require_claims",
    "require_role",
    "require_any_role",
    "require_developer",
    "require_admin",
    "optional_claims",
    "require_claim",
    "require_business_with_status",
    # Resolvers
    "UserResolver",
    "UserResolverFunc",
]
