"""
FastAPI dependency factories for authentication and authorization.

Usage:
    from homelocal_auth import AuthConfig, require_developer, require_claims

    config = AuthConfig(jwks_url="https://auth.example.com/.well-known/jwks.json")

    @app.get("/api/apps")
    async def list_apps(claims: TokenClaims = Depends(require_developer(config))):
        return {"user_id": claims.sub}

    @app.get("/api/admin/users")
    async def list_users(claims: TokenClaims = Depends(require_admin(config))):
        return {"admin_id": claims.sub}
"""

import logging
from collections.abc import Callable, Sequence
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status

from homelocal_auth.claims import TokenClaims
from homelocal_auth.config import AuthConfig
from homelocal_auth.core import AuthenticationError, verify_bearer_token

logger = logging.getLogger(__name__)


def _credentials_exception(detail: str = "Could not validate credentials") -> HTTPException:
    """Create a 401 Unauthorized exception."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden_exception(detail: str) -> HTTPException:
    """Create a 403 Forbidden exception."""
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=detail,
    )


def require_claims(
    config: AuthConfig,
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires valid JWT authentication.

    Returns TokenClaims if the token is valid, raises 401 otherwise.

    Args:
        config: Authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        @app.get("/api/profile")
        async def get_profile(claims: TokenClaims = Depends(require_claims(config))):
            return {"user_id": claims.sub, "roles": claims.roles}
    """

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims:
        try:
            return await verify_bearer_token(authorization, config)
        except AuthenticationError as e:
            logger.warning(f"Authentication failed: {e.message} ({e.code})")
            raise _credentials_exception(e.message)

    return dependency


def require_role(
    config: AuthConfig,
    role: str,
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires a specific role.

    Returns TokenClaims if the token is valid AND has the required role.
    Raises 401 for invalid/missing token, 403 for missing role.

    Args:
        config: Authentication configuration
        role: Required role name

    Returns:
        FastAPI dependency function

    Example:
        @app.get("/api/business/reports")
        async def get_reports(claims: TokenClaims = Depends(require_role(config, "business"))):
            return {"user_id": claims.sub}
    """
    _require_claims = require_claims(config)

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims:
        claims = await _require_claims(authorization)

        if not claims.has_role(role):
            logger.warning(f"User {claims.sub} missing required role: {role}")
            raise _forbidden_exception(f"Role '{role}' required")

        return claims

    return dependency


def require_any_role(
    config: AuthConfig,
    roles: Sequence[str],
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires any of the specified roles.

    Returns TokenClaims if the token is valid AND has at least one of the roles.
    Raises 401 for invalid/missing token, 403 for missing roles.

    Args:
        config: Authentication configuration
        roles: List of acceptable role names (user must have at least one)

    Returns:
        FastAPI dependency function

    Example:
        @app.get("/api/dashboard")
        async def get_dashboard(
            claims: TokenClaims = Depends(require_any_role(config, ["dev", "business"]))
        ):
            return {"user_id": claims.sub}
    """
    _require_claims = require_claims(config)

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims:
        claims = await _require_claims(authorization)

        if not claims.has_any_role(roles):
            logger.warning(f"User {claims.sub} missing required roles: {roles}")
            raise _forbidden_exception(f"One of roles {list(roles)} required")

        return claims

    return dependency


def require_developer(
    config: AuthConfig,
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires the 'dev' role.

    Convenience wrapper for require_role(config, "dev").

    Args:
        config: Authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        @app.post("/api/apps")
        async def create_app(
            app: AppCreate,
            claims: TokenClaims = Depends(require_developer(config))
        ):
            return {"created_by": claims.sub}
    """
    return require_role(config, "dev")


def require_admin(
    config: AuthConfig,
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires the 'admin' role.

    Convenience wrapper for require_role(config, "admin").

    Note: This only checks the JWT 'roles' claim. If you also need to verify
    against an AdminUser database table, combine this with a custom resolver.

    Args:
        config: Authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        @app.get("/admin/approvals")
        async def list_approvals(
            claims: TokenClaims = Depends(require_admin(config))
        ):
            return {"admin_id": claims.sub}
    """
    return require_role(config, "admin")


def optional_claims(
    config: AuthConfig,
) -> Callable[..., TokenClaims | None]:
    """
    Create a FastAPI dependency that optionally validates JWT authentication.

    Returns TokenClaims if a valid token is provided, None if no token or invalid.
    Does NOT raise exceptions for missing/invalid tokens.

    Args:
        config: Authentication configuration

    Returns:
        FastAPI dependency function

    Example:
        @app.get("/api/public")
        async def public_endpoint(claims: TokenClaims | None = Depends(optional_claims(config))):
            if claims:
                return {"user_id": claims.sub, "authenticated": True}
            return {"authenticated": False}
    """

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims | None:
        if not authorization:
            return None

        try:
            return await verify_bearer_token(authorization, config)
        except AuthenticationError:
            return None

    return dependency


def require_claim(
    config: AuthConfig,
    claim_name: str,
    allowed_values: Sequence[Any],
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires a specific claim to have one of the allowed values.

    Returns TokenClaims if the token is valid AND the claim has an allowed value.
    Raises 401 for invalid/missing token, 403 for invalid claim value.

    Args:
        config: Authentication configuration
        claim_name: Name of the claim to check
        allowed_values: List of acceptable values for the claim

    Returns:
        FastAPI dependency function

    Example:
        require_verified = require_claim(config, "address_verified", [True])

        @app.get("/api/verified-only")
        async def verified_endpoint(claims: TokenClaims = Depends(require_verified)):
            return {"user_id": claims.sub}
    """
    _require_claims = require_claims(config)

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims:
        claims = await _require_claims(authorization)

        value = claims.get_claim(claim_name)
        if value not in allowed_values:
            logger.warning(
                f"User {claims.sub} has invalid claim '{claim_name}': {value} not in {list(allowed_values)}"
            )
            raise _forbidden_exception(
                f"Claim '{claim_name}' must be one of: {list(allowed_values)}"
            )

        return claims

    return dependency


def require_business_with_status(
    config: AuthConfig,
    allowed_statuses: Sequence[str] | None = None,
) -> Callable[..., TokenClaims]:
    """
    Create a FastAPI dependency that requires business account type with optional status check.

    Checks both account_type claim (preferred) and business role (backward compatibility).
    If allowed_statuses is provided, also verifies business_status claim.

    Args:
        config: Authentication configuration
        allowed_statuses: List of allowed business_status values.
                         If None, any business account is accepted.

    Returns:
        FastAPI dependency function

    Examples:
        # Any business account (pending, approved, etc.)
        require_any_business = require_business_with_status(config)

        # Only approved businesses
        require_approved = require_business_with_status(config, ["approved"])

        # Pending or approved (can create drafts)
        require_active = require_business_with_status(config, ["pending_approval", "approved"])

        @app.post("/api/listings")
        async def create_listing(claims: TokenClaims = Depends(require_active)):
            return {"created_by": claims.sub}
    """
    _require_claims = require_claims(config)

    async def dependency(
        authorization: Annotated[str | None, Header()] = None,
    ) -> TokenClaims:
        claims = await _require_claims(authorization)

        # Check account_type OR role (for backward compatibility)
        account_type = claims.get_claim("account_type")
        has_business_role = claims.has_role("business")

        if account_type != "business" and not has_business_role:
            logger.warning(f"User {claims.sub} is not a business account")
            raise _forbidden_exception("Business account required")

        # Check status if specified
        if allowed_statuses is not None:
            status = claims.get_claim("business_status")
            if status not in allowed_statuses:
                logger.warning(
                    f"User {claims.sub} has business_status '{status}', required: {list(allowed_statuses)}"
                )
                raise _forbidden_exception(
                    f"Business account must have status: {list(allowed_statuses)}"
                )

        return claims

    return dependency
