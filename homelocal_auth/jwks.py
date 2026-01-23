"""
JWKS client with TTL-based caching and refresh-on-unknown-kid.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from jose import JWTError, jwt

from homelocal_auth.config import AuthConfig

logger = logging.getLogger(__name__)


class JWKSError(Exception):
    """Error fetching or parsing JWKS."""

    pass


@dataclass
class CachedJWKS:
    """Cached JWKS with expiration."""

    keys: dict[str, Any]
    fetched_at: float
    expires_at: float


@dataclass
class JWKSClient:
    """
    JWKS client with TTL-based caching and refresh-on-unknown-kid.

    Features:
    - Caches JWKS for configurable TTL (default: 5 minutes)
    - Automatically refreshes on cache expiry
    - Refresh-on-unknown-kid: if a token's kid is not in cache, refetch once and retry
    - Thread-safe for async usage

    Example:
        client = JWKSClient(config)
        payload = await client.verify_token(token)
    """

    config: AuthConfig
    _cache: CachedJWKS | None = field(default=None, init=False, repr=False)
    _refresh_in_progress: bool = field(default=False, init=False, repr=False)

    async def _fetch_jwks(self) -> dict[str, Any]:
        """
        Fetch JWKS from the configured URL.

        Returns:
            JWKS dictionary with 'keys' array

        Raises:
            JWKSError: If fetch fails or response is invalid
        """
        try:
            async with httpx.AsyncClient(timeout=self.config.http_timeout) as client:
                response = await client.get(self.config.jwks_url)

            if response.status_code != 200:
                raise JWKSError(
                    f"Failed to fetch JWKS: HTTP {response.status_code} from {self.config.jwks_url}"
                )

            jwks = response.json()
            if "keys" not in jwks:
                raise JWKSError("Invalid JWKS response: missing 'keys' field")

            logger.debug(f"Fetched JWKS with {len(jwks['keys'])} keys")
            return jwks

        except httpx.HTTPError as e:
            raise JWKSError(f"HTTP error fetching JWKS: {e}") from e
        except Exception as e:
            if isinstance(e, JWKSError):
                raise
            raise JWKSError(f"Error fetching JWKS: {e}") from e

    async def _get_jwks(self, force_refresh: bool = False) -> dict[str, Any]:
        """
        Get JWKS, using cache if valid.

        Args:
            force_refresh: If True, bypass cache and fetch fresh JWKS

        Returns:
            JWKS dictionary
        """
        now = time.time()

        # Check cache validity
        if not force_refresh and self._cache is not None:
            if now < self._cache.expires_at:
                return self._cache.keys

        # Fetch fresh JWKS
        jwks = await self._fetch_jwks()

        # Update cache
        self._cache = CachedJWKS(
            keys=jwks,
            fetched_at=now,
            expires_at=now + self.config.cache_ttl_seconds,
        )

        logger.info(f"JWKS cache updated, expires in {self.config.cache_ttl_seconds}s")
        return jwks

    def _get_signing_key(self, jwks: dict[str, Any], kid: str | None) -> dict[str, Any]:
        """
        Get the signing key from JWKS that matches the token's key ID.

        Args:
            jwks: JWKS dictionary
            kid: Key ID from token header (may be None)

        Returns:
            The matching key dictionary

        Raises:
            JWKSError: If no matching key found
        """
        keys = jwks.get("keys", [])

        if not keys:
            raise JWKSError("No keys in JWKS")

        # If no kid specified, use first key
        if kid is None:
            logger.debug("No kid in token, using first key")
            return keys[0]

        # Find matching key
        for key in keys:
            if key.get("kid") == kid:
                return key

        # Key not found
        raise JWKSError(f"Key not found for kid: {kid}")

    async def get_signing_key(self, token: str) -> dict[str, Any]:
        """
        Get the signing key for a token, with refresh-on-unknown-kid.

        If the token's kid is not found in the cached JWKS, this will
        fetch fresh JWKS once and retry. This handles key rotation gracefully.

        Args:
            token: JWT token string

        Returns:
            The signing key dictionary

        Raises:
            JWKSError: If key cannot be found even after refresh
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except JWTError as e:
            raise JWKSError(f"Invalid token header: {e}") from e

        kid = unverified_header.get("kid")

        # Try with cached JWKS first
        jwks = await self._get_jwks()
        try:
            return self._get_signing_key(jwks, kid)
        except JWKSError:
            # Key not found - try refreshing JWKS once
            if kid is not None:
                logger.info(f"Key {kid} not in cache, refreshing JWKS")
                jwks = await self._get_jwks(force_refresh=True)
                return self._get_signing_key(jwks, kid)
            raise

    async def verify_token(self, token: str) -> dict[str, Any]:
        """
        Verify a JWT token and return the decoded payload.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            JWKSError: If token verification fails
        """
        signing_key = await self.get_signing_key(token)

        # Build decode options
        options: dict[str, Any] = {
            "verify_aud": self.config.verify_audience,
            "verify_iss": self.config.verify_issuer,
        }

        # Build kwargs for decode
        decode_kwargs: dict[str, Any] = {
            "algorithms": self.config.algorithms,
            "options": options,
        }

        if self.config.verify_audience and self.config.expected_audience:
            decode_kwargs["audience"] = self.config.expected_audience

        if self.config.verify_issuer and self.config.expected_issuer:
            decode_kwargs["issuer"] = self.config.expected_issuer

        try:
            payload = jwt.decode(token, signing_key, **decode_kwargs)
            return payload
        except JWTError as e:
            raise JWKSError(f"Token verification failed: {e}") from e

    def clear_cache(self) -> None:
        """Clear the JWKS cache. Useful for testing or forced refresh."""
        self._cache = None
        logger.debug("JWKS cache cleared")

    @property
    def cache_valid(self) -> bool:
        """Check if the cache is currently valid."""
        if self._cache is None:
            return False
        return time.time() < self._cache.expires_at

    @property
    def cache_expires_in(self) -> float | None:
        """Get seconds until cache expires, or None if no cache."""
        if self._cache is None:
            return None
        remaining = self._cache.expires_at - time.time()
        return max(0.0, remaining)
