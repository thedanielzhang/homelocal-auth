"""
Tests for JWKS client with TTL caching and refresh-on-unknown-kid.
"""

import time

import pytest
import respx
from httpx import Response
from jose import jwt

from homelocal_auth import AuthConfig, JWKSClient

# Test RSA keys (DO NOT use in production)
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MvXJnR2EoFZLqufb
pXBcTm1bGiPqUmSWSx8LWCNLSx9zz9Ne2M+MtLWMbo9X1xR6lEK8k6sVYP0uxGVL
BqRtCAqKjsAkRNthIvfri0kBI0cvTJSgVs9V3DRcaLU9cPG8PQqQaJlE7qpVJo2y
TLmfNP+5kA0e8MthKlxSN/PYNX9rewS7NbeTwNaJ1Wj1LewBkcRig3FxXvp2PV6I
JZfg7fRi7penPQCDoEi/1Fpss6uhFGCuJkWMoqWLwHIHdIwEDfYXLPHEEP5x/h8k
MqFsNXCPsufP5dCN8EZPYqnXsmXLccyzVJEzQwIDAQABAoIBAFTOYQHot0DfYsSB
rBvsp8OOLAE8BLUngJFKCYR+SHV6GSpXfSPjQWmFsLRXcV6+zVGL0CSuV+vHPfkm
YtPTlWr+iu8TAUCE7R+LlzCG2Qt3Q89VElAba4jUMGDdA8UKJuxvpCA5d3YUGVVL
aP6HpaDCplmfC1wQG4UgyJZIBKLfSCnTfPCMGhfKqPpGCU7bUVPCMK5BSeJJH4bO
OKvC6EfHqCzLbEM0qMXGsFS0wZXdEN3hflXyBNUd9mScuN0Xq1M9oUP/wo+dqKbw
mkMCTCONL2kZCLgCRwO8zP+P52CfV8KVqrCBpMC6T5wqIPTNtGj8I1gMnYZJCP0U
YVSFJhECgYEA7jJb3wudL4eK2FNjSPrYQzIhr8NuhnOUL7qsR+/Z5JCLoFq7tPUL
GneQNLoUdP+86x9nELMZX3F6jJZPbUsW0k5H0DNdxCKjyFc0QuAaHkO9kvVbN3f0
J0w5mMPKWYRIc2oOsDdUa9M7eNUq9PyjJKCvKM1jE3CFxpVBiSkT5qMCgYEA4YKm
c9cMFl6MhpHBCPnklZp3ptyHx0y06H8qDZhVGpkKNh0ey4NlntPt3xAqgt7+JEUx
WrD0nq6dN0eZGOdJ+kAolMJvJqkE2+pVQNqYOSEB3DZba+WBqvPhZt5N+0wl0/s5
K06awHrvenCc5hVNQGFPiLEzlgNLYclp8LtPHeECgYBEU7CrJXdpThJcH3BxYVBb
XWFT7OdnzK4Ou0lE7xXAHmM9DLVq0rPCVYtoGi0Lf3vT2YYKmW+3UjAcBXIBPO8U
hPBzgCgG11nSWYPstXy67V4wPIaU5saJ/pkMnUlThCmqTqJXR2Q+bQdQqsRHLxYw
Pk7dzjr5iwZGBZiQeGV4GwKBgDlKJFz9NqaYyKLPXVmRnA1KJemPCKWOA9rTQrBw
J5Y0qB+E5gtqLh1S0dTi7wa6eSQ2cxvPSVQ8xYP0Y2eUbeIotmjPgCrAfUaMn3xZ
JAh7SaMzD+RBOvUXauuJKlPPKnLhMgl9v8FMcn3QrR2e3YCCLer7q2WXQVURU9nk
JvAhAoGBALdV8gEs1EA1VIP+QxqU0L1D7atAEHCsPLptihrVqUlCBfAkPSQm8dP+
y/VN6gaHDQ0CArlYsff9t7sv1bH7Nv8KTRLF0DT85Z9pwqeiH7MTIlmgpiuM6YXM
5HvdjdmVLlqvN1EaqJvfvBT1e6YQaDjdO0fQOhvqC/R7p4RFxMLB
-----END RSA PRIVATE KEY-----"""

TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
F8PbnGy0AHB7MvXJnR2EoFZLqufbpXBcTm1bGiPqUmSWSx8LWCNLSx9zz9Ne2M+M
tLWMbo9X1xR6lEK8k6sVYP0uxGVLBqRtCAqKjsAkRNthIvfri0kBI0cvTJSgVs9V
3DRcaLU9cPG8PQqQaJlE7qpVJo2yTLmfNP+5kA0e8MthKlxSN/PYNX9rewS7NbeT
wNaJ1Wj1LewBkcRig3FxXvp2PV6IJZfg7fRi7penPQCDoEi/1Fpss6uhFGCuJkWM
oqWLwHIHdIwEDfYXLPHEEP5x/h8kMqFsNXCPsufP5dCN8EZPYqnXsmXLccyzVJEz
QwIDAQAB
-----END PUBLIC KEY-----"""

TEST_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "0Z3VS5JJcds3xfn_ygWyF8PbnGy0AHB7MvXJnR2EoFZLqufbpXBcTm1bGiPqUmSWSx8LWCNLSx9zz9Ne2M-MtLWMbo9X1xR6lEK8k6sVYP0uxGVLBqRtCAqKjsAkRNthIvfri0kBI0cvTJSgVs9V3DRcaLU9cPG8PQqQaJlE7qpVJo2yTLmfNP-5kA0e8MthKlxSN_PYNX9rewS7NbeTwNaJ1Wj1LewBkcRig3FxXvp2PV6IJZfg7fRi7penPQCDoEi_1Fpss6uhFGCuJkWMoqWLwHIHdIwEDfYXLPHEEP5x_h8kMqFsNXCPsufP5dCN8EZPYqnXsmXLccyzVJEzQw",
            "e": "AQAB",
        }
    ]
}


def create_test_token(claims: dict, kid: str = "key-1") -> str:
    """Create a test JWT token."""
    return jwt.encode(
        claims,
        TEST_PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": kid},
    )


@pytest.fixture
def config():
    """Create test config."""
    return AuthConfig(
        jwks_url="https://auth.test.com/.well-known/jwks.json",
        cache_ttl_seconds=10,
        http_timeout=5.0,
    )


@pytest.fixture
def client(config):
    """Create test JWKS client."""
    return JWKSClient(config)


@respx.mock
@pytest.mark.asyncio
async def test_fetch_jwks_success(client):
    """Test successful JWKS fetch."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({"sub": "user-123", "exp": int(time.time()) + 3600})
    payload = await client.verify_token(token)

    assert payload["sub"] == "user-123"


@respx.mock
@pytest.mark.asyncio
async def test_jwks_cache_ttl(config):
    """Test that JWKS is cached and respects TTL."""
    route = respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    client = JWKSClient(config)
    token = create_test_token({"sub": "user-123", "exp": int(time.time()) + 3600})

    # First call - should fetch
    await client.verify_token(token)
    assert route.call_count == 1

    # Second call - should use cache
    await client.verify_token(token)
    assert route.call_count == 1

    # Verify cache is valid
    assert client.cache_valid
    assert client.cache_expires_in is not None
    assert client.cache_expires_in > 0


@respx.mock
@pytest.mark.asyncio
async def test_refresh_on_unknown_kid(config):
    """Test that unknown kid triggers JWKS refresh."""
    # First return JWKS without the key, then with it
    jwks_without_key = {"keys": [{"kty": "RSA", "kid": "old-key", "use": "sig"}]}

    route = respx.get("https://auth.test.com/.well-known/jwks.json")
    route.side_effect = [
        Response(200, json=jwks_without_key),
        Response(200, json=TEST_JWKS),
    ]

    client = JWKSClient(config)
    token = create_test_token({"sub": "user-123", "exp": int(time.time()) + 3600}, kid="key-1")

    # Should fetch twice: initial + refresh on unknown kid
    payload = await client.verify_token(token)
    assert payload["sub"] == "user-123"
    assert route.call_count == 2


@respx.mock
@pytest.mark.asyncio
async def test_clear_cache(client):
    """Test cache clearing."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({"sub": "user-123", "exp": int(time.time()) + 3600})
    await client.verify_token(token)

    assert client.cache_valid
    client.clear_cache()
    assert not client.cache_valid


@respx.mock
@pytest.mark.asyncio
async def test_jwks_fetch_failure(client):
    """Test handling of JWKS fetch failure."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(500, text="Internal Server Error")
    )

    token = create_test_token({"sub": "user-123", "exp": int(time.time()) + 3600})

    from homelocal_auth.jwks import JWKSError

    with pytest.raises(JWKSError) as exc_info:
        await client.verify_token(token)

    assert "HTTP 500" in str(exc_info.value)


@respx.mock
@pytest.mark.asyncio
async def test_expired_token_rejected(client):
    """Test that expired tokens are rejected."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    # Token expired 1 hour ago
    token = create_test_token({"sub": "user-123", "exp": int(time.time()) - 3600})

    from homelocal_auth.jwks import JWKSError

    with pytest.raises(JWKSError) as exc_info:
        await client.verify_token(token)

    assert "expired" in str(exc_info.value).lower()
