"""
Tests for FastAPI dependencies.
"""

import time

import pytest
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from jose import jwt

from homelocal_auth import (
    AuthConfig,
    TokenClaims,
    require_admin,
    require_any_role,
    require_claims,
    require_developer,
    require_role,
)
from homelocal_auth.fastapi import optional_claims

# Same test keys as test_jwks.py
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
        cache_ttl_seconds=300,
    )


@pytest.fixture
def app(config):
    """Create test FastAPI app."""
    app = FastAPI()

    @app.get("/public")
    async def public():
        return {"message": "public"}

    @app.get("/protected")
    async def protected(claims: TokenClaims = Depends(require_claims(config))):
        return {"user_id": claims.sub, "roles": claims.roles}

    @app.get("/developer")
    async def developer(claims: TokenClaims = Depends(require_developer(config))):
        return {"developer_id": claims.sub}

    @app.get("/admin")
    async def admin(claims: TokenClaims = Depends(require_admin(config))):
        return {"admin_id": claims.sub}

    @app.get("/business")
    async def business(claims: TokenClaims = Depends(require_role(config, "business"))):
        return {"business_user_id": claims.sub}

    @app.get("/dev-or-admin")
    async def dev_or_admin(claims: TokenClaims = Depends(require_any_role(config, ["dev", "admin"]))):
        return {"user_id": claims.sub}

    @app.get("/optional")
    async def optional(claims: TokenClaims | None = Depends(optional_claims(config))):
        if claims:
            return {"authenticated": True, "user_id": claims.sub}
        return {"authenticated": False}

    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@respx.mock
def test_public_endpoint_no_auth(client):
    """Test public endpoint works without auth."""
    response = client.get("/public")
    assert response.status_code == 200
    assert response.json() == {"message": "public"}


@respx.mock
def test_protected_endpoint_missing_auth(client):
    """Test protected endpoint returns 401 without auth."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    response = client.get("/protected")
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


@respx.mock
def test_protected_endpoint_valid_token(client):
    """Test protected endpoint with valid token."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "dev"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"user_id": "user-123", "roles": ["default", "dev"]}


@respx.mock
def test_developer_endpoint_with_dev_role(client):
    """Test developer endpoint with dev role."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "dev-user",
        "roles": ["default", "dev"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/developer", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"developer_id": "dev-user"}


@respx.mock
def test_developer_endpoint_without_dev_role(client):
    """Test developer endpoint returns 403 without dev role."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/developer", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    assert "dev" in response.json()["detail"].lower()


@respx.mock
def test_admin_endpoint_with_admin_role(client):
    """Test admin endpoint with admin role."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "admin-user",
        "roles": ["default", "admin"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"admin_id": "admin-user"}


@respx.mock
def test_admin_endpoint_without_admin_role(client):
    """Test admin endpoint returns 403 without admin role."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "dev"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


@respx.mock
def test_any_role_endpoint_with_matching_role(client):
    """Test any-role endpoint with one matching role."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "dev"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/dev-or-admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


@respx.mock
def test_any_role_endpoint_without_matching_role(client):
    """Test any-role endpoint returns 403 without matching roles."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/dev-or-admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


@respx.mock
def test_optional_claims_without_token(client):
    """Test optional claims returns None without token."""
    response = client.get("/optional")
    assert response.status_code == 200
    assert response.json() == {"authenticated": False}


@respx.mock
def test_optional_claims_with_valid_token(client):
    """Test optional claims with valid token."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": [],
        "exp": int(time.time()) + 3600,
    })

    response = client.get("/optional", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "user_id": "user-123"}


@respx.mock
def test_invalid_token_format(client):
    """Test invalid token format returns 401."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    response = client.get("/protected", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401


@respx.mock
def test_invalid_auth_scheme(client):
    """Test invalid auth scheme returns 401."""
    response = client.get("/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401
