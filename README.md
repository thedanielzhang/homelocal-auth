# homelocal-auth

Reusable JWT authentication library for Home.Local FastAPI services.

## Features

- **JWKS-based JWT validation** with TTL caching
- **Refresh-on-unknown-kid**: Automatically refetches JWKS when encountering unknown key IDs (handles key rotation)
- **FastAPI dependency factories** for role-based access control
- **Not coupled to SQLAlchemy**: Use pluggable resolvers for database integration
- **Type-safe**: Full type annotations and py.typed marker

## Installation

```bash
# From private PyPI
pip install homelocal-auth==0.1.0

# Or with pip index URL
pip install homelocal-auth --index-url https://pypi.homelocal.internal/simple/
```

## Quick Start

```python
from fastapi import Depends, FastAPI
from homelocal_auth import AuthConfig, TokenClaims, require_developer, require_admin

# Configure once
config = AuthConfig(
    jwks_url="https://auth.example.com/.well-known/jwks.json",
    cache_ttl_seconds=300,  # Cache JWKS for 5 minutes
)

app = FastAPI()

@app.get("/api/apps")
async def list_apps(claims: TokenClaims = Depends(require_developer(config))):
    """Requires 'dev' role in JWT."""
    return {"user_id": claims.sub, "roles": claims.roles}

@app.get("/admin/users")
async def list_users(claims: TokenClaims = Depends(require_admin(config))):
    """Requires 'admin' role in JWT."""
    return {"admin_id": claims.sub}
```

## API Reference

### Configuration

```python
from homelocal_auth import AuthConfig

config = AuthConfig(
    jwks_url="https://auth.example.com/.well-known/jwks.json",
    cache_ttl_seconds=300,          # JWKS cache TTL (default: 300)
    http_timeout=10.0,              # HTTP timeout for JWKS fetch (default: 10.0)
    verify_issuer=False,            # Verify 'iss' claim (default: False)
    expected_issuer=None,           # Expected issuer value
    verify_audience=False,          # Verify 'aud' claim (default: False)
    expected_audience=None,         # Expected audience value
    algorithms=["RS256"],           # Allowed JWT algorithms
)
```

### FastAPI Dependencies

| Dependency | Description |
|------------|-------------|
| `require_claims(config)` | Requires valid JWT, returns `TokenClaims` |
| `require_developer(config)` | Requires 'dev' role |
| `require_admin(config)` | Requires 'admin' role |
| `require_role(config, "role")` | Requires specific role |
| `require_any_role(config, ["a", "b"])` | Requires any of the roles |
| `optional_claims(config)` | Returns `TokenClaims | None`, doesn't raise |

### TokenClaims

```python
from homelocal_auth import TokenClaims

# TokenClaims properties
claims.sub          # str: User ID
claims.roles        # list[str]: Role names
claims.exp          # int: Expiration timestamp
claims.email        # str | None: Email from payload
claims.name         # str | None: Name from payload
claims.raw_payload  # dict: Full JWT payload

# TokenClaims methods
claims.has_role("admin")           # bool
claims.has_any_role(["dev", "admin"])  # bool
claims.has_all_roles(["dev", "business"])  # bool
claims.is_admin                    # bool (property)
claims.is_developer                # bool (property)
claims.get_claim("custom_field")   # Any
```

### User Resolution (Database Integration)

The library doesn't depend on SQLAlchemy. Use resolvers to integrate with your database:

```python
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from homelocal_auth import TokenClaims, require_developer

from myapp.database import get_db
from myapp.models import User

async def get_current_user(
    claims: TokenClaims = Depends(require_developer(config)),
    db: Session = Depends(get_db),
) -> User:
    """Resolve database User from token claims."""
    user = db.query(User).filter(User.id == claims.sub).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user

@app.get("/api/profile")
async def get_profile(user: User = Depends(get_current_user)):
    return {"name": user.name, "email": user.email}
```

### Direct Token Verification

```python
from homelocal_auth import verify_bearer_token, AuthenticationError

try:
    claims = await verify_bearer_token(
        authorization="Bearer eyJ...",
        config=config,
    )
    print(f"User: {claims.sub}")
except AuthenticationError as e:
    print(f"Auth failed: {e.message} ({e.code})")
```

### JWKS Cache Control

```python
from homelocal_auth import get_jwks_client, clear_jwks_cache

# Get client for a config
client = get_jwks_client(config)

# Check cache status
print(f"Cache valid: {client.cache_valid}")
print(f"Expires in: {client.cache_expires_in}s")

# Clear cache (useful for testing or forced refresh)
clear_jwks_cache(config)
```

## HTTP Status Codes

| Status | Condition |
|--------|-----------|
| 401 Unauthorized | Missing Authorization header |
| 401 Unauthorized | Invalid token format |
| 401 Unauthorized | Token verification failed |
| 401 Unauthorized | Token expired |
| 403 Forbidden | Missing required role |

## Migration from deploy-service

If migrating from the existing `deploy-service/app/dependencies/auth.py`:

```python
# Before (deploy-service)
from app.dependencies.auth import get_current_developer

# After (using homelocal-auth)
from homelocal_auth import AuthConfig, require_developer

config = AuthConfig(jwks_url=f"{settings.auth_service_url}/.well-known/jwks.json")

# Create compatibility wrapper
async def get_current_developer(
    claims: TokenClaims = Depends(require_developer(config)),
    db: Session = Depends(get_db),
) -> User:
    user = db.query(User).filter(User.id == claims.sub).first()
    if not user:
        raise HTTPException(401, "User not found")
    return user
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -v

# Type check
mypy homelocal_auth

# Lint
ruff check homelocal_auth
```

## Publishing

See [PUBLISHING.md](./PUBLISHING.md) for instructions on publishing to private PyPI.
