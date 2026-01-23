"""
Core authentication functions.
"""

import logging
from functools import lru_cache

from homelocal_auth.claims import TokenClaims
from homelocal_auth.config import AuthConfig
from homelocal_auth.jwks import JWKSClient, JWKSError

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """
    Authentication failed.

    Attributes:
        message: Human-readable error message
        code: Error code for programmatic handling
    """

    def __init__(self, message: str, code: str = "auth_failed") -> None:
        super().__init__(message)
        self.message = message
        self.code = code


@lru_cache(maxsize=16)
def _get_jwks_client(config: AuthConfig) -> JWKSClient:
    """
    Get or create a cached JWKSClient for the given config.

    This ensures we reuse JWKS clients (and their caches) for the same config.
    """
    return JWKSClient(config)


def parse_bearer_token(authorization: str | None) -> str:
    """
    Parse Bearer token from Authorization header.

    Args:
        authorization: Authorization header value (e.g., "Bearer eyJ...")

    Returns:
        The token string

    Raises:
        AuthenticationError: If header is missing or malformed
    """
    if not authorization:
        raise AuthenticationError("Missing authorization header", code="missing_header")

    parts = authorization.split()

    if len(parts) != 2:
        raise AuthenticationError(
            "Invalid authorization header format", code="invalid_header_format"
        )

    scheme, token = parts

    if scheme.lower() != "bearer":
        raise AuthenticationError(
            f"Invalid authentication scheme: {scheme}, expected Bearer",
            code="invalid_scheme",
        )

    if not token:
        raise AuthenticationError("Empty token", code="empty_token")

    return token


async def verify_bearer_token(
    authorization: str | None,
    config: AuthConfig,
) -> TokenClaims:
    """
    Verify a Bearer token from an Authorization header.

    This is the main entry point for token verification. It:
    1. Parses the Bearer token from the Authorization header
    2. Fetches/uses cached JWKS
    3. Verifies the JWT signature and claims
    4. Returns parsed TokenClaims

    Args:
        authorization: Authorization header value (e.g., "Bearer eyJ...")
        config: Authentication configuration

    Returns:
        TokenClaims with parsed and validated claims

    Raises:
        AuthenticationError: If authentication fails for any reason

    Example:
        try:
            claims = await verify_bearer_token(request.headers.get("Authorization"), config)
            print(f"User: {claims.sub}, Roles: {claims.roles}")
        except AuthenticationError as e:
            print(f"Auth failed: {e.message} ({e.code})")
    """
    # Parse token from header
    token = parse_bearer_token(authorization)

    # Get JWKS client for this config
    client = _get_jwks_client(config)

    try:
        # Verify token and get payload
        payload = await client.verify_token(token)

        # Parse claims from payload
        claims = TokenClaims.from_payload(payload)

        logger.debug(f"Token verified for user {claims.sub}")
        return claims

    except JWKSError as e:
        logger.warning(f"Token verification failed: {e}")
        raise AuthenticationError(str(e), code="token_invalid") from e
    except ValueError as e:
        logger.warning(f"Token claims invalid: {e}")
        raise AuthenticationError(str(e), code="claims_invalid") from e


def get_jwks_client(config: AuthConfig) -> JWKSClient:
    """
    Get the JWKSClient for a config.

    Useful for direct JWKS operations like cache clearing.

    Args:
        config: Authentication configuration

    Returns:
        JWKSClient instance (cached per config)
    """
    return _get_jwks_client(config)


def clear_jwks_cache(config: AuthConfig) -> None:
    """
    Clear the JWKS cache for a specific config.

    Args:
        config: Authentication configuration
    """
    client = _get_jwks_client(config)
    client.clear_cache()


def clear_all_jwks_caches() -> None:
    """Clear all JWKS caches (clears the client cache)."""
    _get_jwks_client.cache_clear()
