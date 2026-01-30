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
    require_business_with_status,
    require_claim,
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


# =============================================================================
# Tests for require_claim()
# =============================================================================


@pytest.fixture
def app_with_claim_checks(config):
    """Create test FastAPI app with require_claim endpoints."""
    app = FastAPI()

    @app.get("/verified")
    async def verified(
        claims: TokenClaims = Depends(require_claim(config, "address_verified", [True]))
    ):
        return {"user_id": claims.sub, "verified": True}

    @app.get("/active-status")
    async def active_status(
        claims: TokenClaims = Depends(
            require_claim(config, "business_status", ["pending_approval", "approved"])
        )
    ):
        return {"user_id": claims.sub, "status": claims.get_claim("business_status")}

    return app


@pytest.fixture
def client_claim_checks(app_with_claim_checks):
    """Create test client for claim check tests."""
    return TestClient(app_with_claim_checks)


@respx.mock
def test_require_claim_with_matching_value(client_claim_checks):
    """Test require_claim allows matching value."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "address_verified": True,
        "exp": int(time.time()) + 3600,
    })

    response = client_claim_checks.get(
        "/verified",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"user_id": "user-123", "verified": True}


@respx.mock
def test_require_claim_with_non_matching_value(client_claim_checks):
    """Test require_claim returns 403 for non-matching value."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "address_verified": False,
        "exp": int(time.time()) + 3600,
    })

    response = client_claim_checks.get(
        "/verified",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "address_verified" in response.json()["detail"]


@respx.mock
def test_require_claim_with_missing_claim(client_claim_checks):
    """Test require_claim returns 403 when claim is missing."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "exp": int(time.time()) + 3600,
    })

    response = client_claim_checks.get(
        "/verified",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


@respx.mock
def test_require_claim_with_one_of_allowed_values(client_claim_checks):
    """Test require_claim allows any of the allowed values."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    # Test with "pending_approval"
    token1 = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "business_status": "pending_approval",
        "exp": int(time.time()) + 3600,
    })

    response1 = client_claim_checks.get(
        "/active-status",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert response1.status_code == 200
    assert response1.json()["status"] == "pending_approval"

    # Test with "approved"
    token2 = create_test_token({
        "sub": "user-456",
        "roles": ["default"],
        "business_status": "approved",
        "exp": int(time.time()) + 3600,
    })

    response2 = client_claim_checks.get(
        "/active-status",
        headers={"Authorization": f"Bearer {token2}"}
    )
    assert response2.status_code == 200
    assert response2.json()["status"] == "approved"


@respx.mock
def test_require_claim_rejects_non_allowed_value(client_claim_checks):
    """Test require_claim rejects values not in allowed list."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "business_status": "suspended",
        "exp": int(time.time()) + 3600,
    })

    response = client_claim_checks.get(
        "/active-status",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "business_status" in response.json()["detail"]


# =============================================================================
# Tests for require_business_with_status()
# =============================================================================


@pytest.fixture
def app_with_business_status(config):
    """Create test FastAPI app with require_business_with_status endpoints."""
    app = FastAPI()

    @app.get("/any-business")
    async def any_business(
        claims: TokenClaims = Depends(require_business_with_status(config))
    ):
        return {
            "user_id": claims.sub,
            "account_type": claims.get_claim("account_type"),
            "business_status": claims.get_claim("business_status"),
        }

    @app.get("/approved-business")
    async def approved_business(
        claims: TokenClaims = Depends(
            require_business_with_status(config, ["approved"])
        )
    ):
        return {"user_id": claims.sub, "approved": True}

    @app.get("/active-business")
    async def active_business(
        claims: TokenClaims = Depends(
            require_business_with_status(config, ["pending_approval", "approved"])
        )
    ):
        return {
            "user_id": claims.sub,
            "status": claims.get_claim("business_status"),
        }

    return app


@pytest.fixture
def client_business_status(app_with_business_status):
    """Create test client for business status tests."""
    return TestClient(app_with_business_status)


@respx.mock
def test_require_business_with_account_type(client_business_status):
    """Test require_business_with_status allows business account_type."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "account_type": "business",
        "business_status": "pending_approval",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/any-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["account_type"] == "business"


@respx.mock
def test_require_business_with_business_role_backward_compat(client_business_status):
    """Test require_business_with_status allows business role (backward compat)."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    # Token with business role but no account_type (legacy token)
    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "business_status": "approved",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/any-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200


@respx.mock
def test_require_business_rejects_personal_account(client_business_status):
    """Test require_business_with_status rejects personal accounts."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default"],
        "account_type": "personal",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/any-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "business account required" in response.json()["detail"].lower()


@respx.mock
def test_require_business_approved_allows_approved(client_business_status):
    """Test require_business_with_status(['approved']) allows approved businesses."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "account_type": "business",
        "business_status": "approved",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/approved-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["approved"] is True


@respx.mock
def test_require_business_approved_rejects_pending(client_business_status):
    """Test require_business_with_status(['approved']) rejects pending businesses."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "account_type": "business",
        "business_status": "pending_approval",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/approved-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403
    assert "status" in response.json()["detail"].lower()


@respx.mock
def test_require_business_active_allows_pending(client_business_status):
    """Test require_business_with_status(['pending_approval', 'approved']) allows pending."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "account_type": "business",
        "business_status": "pending_approval",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/active-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "pending_approval"


@respx.mock
def test_require_business_active_allows_approved(client_business_status):
    """Test require_business_with_status(['pending_approval', 'approved']) allows approved."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "account_type": "business",
        "business_status": "approved",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/active-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["status"] == "approved"


@respx.mock
def test_require_business_active_rejects_suspended(client_business_status):
    """Test require_business_with_status(['pending_approval', 'approved']) rejects suspended."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    token = create_test_token({
        "sub": "user-123",
        "roles": ["default", "business"],
        "account_type": "business",
        "business_status": "suspended",
        "exp": int(time.time()) + 3600,
    })

    response = client_business_status.get(
        "/active-business",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403


@respx.mock
def test_require_business_no_auth(client_business_status):
    """Test require_business_with_status returns 401 without auth."""
    respx.get("https://auth.test.com/.well-known/jwks.json").mock(
        return_value=Response(200, json=TEST_JWKS)
    )

    response = client_business_status.get("/any-business")
    assert response.status_code == 401
