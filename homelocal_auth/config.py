"""
Authentication configuration.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthConfig:
    """
    Configuration for JWT authentication.

    Attributes:
        jwks_url: URL to fetch JWKS (e.g., "https://auth.example.com/.well-known/jwks.json")
        cache_ttl_seconds: How long to cache JWKS before refreshing (default: 300 = 5 minutes)
        http_timeout: Timeout for JWKS fetch requests (default: 10.0 seconds)
        verify_issuer: Whether to verify the 'iss' claim (default: False for backwards compat)
        expected_issuer: Expected issuer value if verify_issuer is True
        verify_audience: Whether to verify the 'aud' claim (default: False for backwards compat)
        expected_audience: Expected audience value if verify_audience is True
        algorithms: Allowed JWT algorithms (default: ("RS256",))

    Example:
        config = AuthConfig(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            cache_ttl_seconds=300,
            verify_issuer=True,
            expected_issuer="https://auth.example.com",
        )
    """

    jwks_url: str
    cache_ttl_seconds: int = 300
    http_timeout: float = 10.0
    verify_issuer: bool = False
    expected_issuer: str | None = None
    verify_audience: bool = False
    expected_audience: str | None = None
    algorithms: tuple[str, ...] = ("RS256",)

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.jwks_url:
            raise ValueError("jwks_url is required")
        if self.verify_issuer and not self.expected_issuer:
            raise ValueError("expected_issuer required when verify_issuer is True")
        if self.verify_audience and not self.expected_audience:
            raise ValueError("expected_audience required when verify_audience is True")
        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds must be non-negative")
        if self.http_timeout <= 0:
            raise ValueError("http_timeout must be positive")
