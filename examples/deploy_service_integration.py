"""
Example: Integrating homelocal-auth into deploy-service

This file shows how to adapt deploy-service/app/dependencies/auth.py
to use the homelocal-auth package while maintaining backwards compatibility.

INSTALLATION:
1. Add to deploy-service/requirements.txt or pyproject.toml:
   homelocal-auth==0.1.0

2. Configure pip to use private registry (see PUBLISHING.md)

3. Replace deploy-service/app/dependencies/auth.py with this pattern
"""

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

# Import from the new package
from homelocal_auth import (
    AuthConfig,
    TokenClaims,
    require_admin as _require_admin_role,
    require_any_role as _require_any_role,
    require_claims,
    require_developer as _require_developer_role,
    require_role as _require_role,
)
from homelocal_auth.fastapi import optional_claims

# Local imports (unchanged)
from ..config import settings
from ..database import get_db
from ..models import AdminUser, User

logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

# Create auth config from settings
auth_config = AuthConfig(
    jwks_url=f"{settings.auth_service_url}/.well-known/jwks.json",
    cache_ttl_seconds=300,  # 5 minutes (new: was infinite before)
    http_timeout=10.0,
    # Keep issuer/audience verification OFF for backwards compatibility
    verify_issuer=False,
    verify_audience=False,
)


# =============================================================================
# Backwards-Compatible Dependencies
# =============================================================================


async def get_current_developer(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency to get the current authenticated developer.

    BACKWARDS COMPATIBLE: Same signature as before, returns User model.

    Internally uses homelocal-auth for JWT validation, then resolves User from DB.
    """
    # Get claims using the library
    _get_claims = require_claims(auth_config)
    claims = await _get_claims(authorization)

    # Resolve User from database
    user = db.query(User).filter(User.id == claims.sub).first()

    if not user:
        logger.warning(f"User not found for id: {claims.sub}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    logger.debug(f"Authenticated developer: {user.email}")
    return user


async def get_optional_developer(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> User | None:
    """
    Dependency to optionally get the current authenticated developer.

    BACKWARDS COMPATIBLE: Same signature as before.
    """
    _get_optional = optional_claims(auth_config)
    claims = await _get_optional(authorization)

    if claims is None:
        return None

    user = db.query(User).filter(User.id == claims.sub).first()
    return user


async def require_admin_developer(
    user: User = Depends(get_current_developer),
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency to require the current user to be an admin.

    BACKWARDS COMPATIBLE: Checks AdminUser table, not just JWT claim.
    """
    admin = db.query(AdminUser).filter(AdminUser.user_id == user.id).first()

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    if not admin.is_active:
        logger.warning(f"Inactive admin attempted access: {user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is inactive",
        )

    return user


# =============================================================================
# New Role-Aware Dependencies (using library directly)
# =============================================================================


# Get claims with roles (no DB lookup, just JWT validation)
get_claims = require_claims(auth_config)

# Require specific roles (JWT-only, no DB lookup)
require_dev_role = _require_developer_role(auth_config)
require_admin_role = _require_admin_role(auth_config)


def require_role(role: str):
    """Factory for requiring a specific role."""
    return _require_role(auth_config, role)


def require_any_role(roles: list[str]):
    """Factory for requiring any of the specified roles."""
    return _require_any_role(auth_config, roles)


# =============================================================================
# Role-Aware User Resolution (Combines JWT + DB)
# =============================================================================


async def get_authenticated_user(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> tuple[User, TokenClaims]:
    """
    Get authenticated user with token claims.

    Returns both the User model and TokenClaims for role checking.

    Example:
        @router.get("/endpoint")
        async def endpoint(auth: tuple[User, TokenClaims] = Depends(get_authenticated_user)):
            user, claims = auth
            if claims.is_admin:
                # admin-specific logic
    """
    _get_claims = require_claims(auth_config)
    claims = await _get_claims(authorization)

    user = db.query(User).filter(User.id == claims.sub).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user, claims


# =============================================================================
# Admin Auth (for admin-specific routers)
# =============================================================================


async def get_current_admin(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> AdminUser:
    """
    Dependency for admin endpoints.

    BACKWARDS COMPATIBLE: Returns AdminUser model.
    """
    _get_claims = require_claims(auth_config)
    claims = await _get_claims(authorization)

    admin = (
        db.query(AdminUser)
        .join(User)
        .filter(User.id == claims.sub)
        .first()
    )

    if not admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    if not admin.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin account is inactive",
        )

    return admin


async def require_super_admin(
    admin: AdminUser = Depends(get_current_admin),
) -> AdminUser:
    """Require super admin role."""
    if admin.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required",
        )
    return admin


# =============================================================================
# Legacy Exports (for gradual migration)
# =============================================================================

# Re-export types for backwards compatibility
from homelocal_auth import AuthenticationError  # noqa: E402, F401

# Keep the AuthenticatedUser dataclass for any code that uses it
from dataclasses import dataclass  # noqa: E402


@dataclass
class AuthenticatedUser:
    """
    DEPRECATED: Use TokenClaims from homelocal-auth instead.

    Kept for backwards compatibility during migration.
    """

    user: User
    roles: list[str]
    token_payload: dict

    def has_role(self, role: str) -> bool:
        return role in self.roles

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    @property
    def is_developer(self) -> bool:
        return "dev" in self.roles


# =============================================================================
# Cache Control (exposed for testing)
# =============================================================================


def clear_jwks_cache() -> None:
    """Clear the JWKS cache. Useful for testing or key rotation."""
    from homelocal_auth import clear_jwks_cache as _clear

    _clear(auth_config)
