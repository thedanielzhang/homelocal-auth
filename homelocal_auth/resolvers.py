"""
User resolver protocols for database integration.

This module provides protocols and utilities for resolving database user objects
from TokenClaims. The library itself is not coupled to SQLAlchemy or any specific
ORM - consumers provide their own resolver implementations.

Usage:
    from homelocal_auth import TokenClaims, require_claims
    from homelocal_auth.resolvers import with_user_resolver

    # Define your resolver
    async def resolve_user(claims: TokenClaims, db: Session) -> User:
        user = db.query(User).filter(User.id == claims.sub).first()
        if not user:
            raise HTTPException(401, "User not found")
        return user

    # Create dependency that returns resolved user
    get_current_user = with_user_resolver(require_claims(config), resolve_user)

    @app.get("/api/profile")
    async def get_profile(user: User = Depends(get_current_user)):
        return {"name": user.name}
"""

from collections.abc import Awaitable, Callable
from typing import Any, Protocol, TypeVar

from homelocal_auth.claims import TokenClaims

# Type variable for user models
UserT = TypeVar("UserT")


class UserResolver(Protocol[UserT]):
    """
    Protocol for user resolver callables.

    A user resolver takes TokenClaims and returns a user object.
    It may accept additional dependencies (like database sessions).

    The resolver should raise appropriate HTTPExceptions if the user
    cannot be found or is invalid.
    """

    async def __call__(self, claims: TokenClaims, **kwargs: Any) -> UserT:
        """
        Resolve a user from token claims.

        Args:
            claims: Validated token claims
            **kwargs: Additional dependencies (e.g., db session)

        Returns:
            User object

        Raises:
            HTTPException: If user cannot be resolved
        """
        ...


# Simpler type alias for resolver functions
UserResolverFunc = Callable[[TokenClaims], Awaitable[UserT]]


def with_user_resolver(
    claims_dependency: Callable[..., TokenClaims],
    resolver: UserResolverFunc[UserT],
) -> Callable[..., UserT]:
    """
    Wrap a claims dependency with a user resolver.

    This creates a new dependency that:
    1. Gets TokenClaims using the provided dependency
    2. Passes claims to the resolver to get a user object
    3. Returns the user object

    Args:
        claims_dependency: A dependency that returns TokenClaims (e.g., require_claims(config))
        resolver: An async function that takes TokenClaims and returns a user

    Returns:
        A new dependency function that returns the resolved user

    Example:
        # Your resolver function
        async def resolve_user(claims: TokenClaims) -> User:
            user = await user_repo.get_by_id(claims.sub)
            if not user:
                raise HTTPException(404, "User not found")
            return user

        # Create wrapped dependency
        get_current_user = with_user_resolver(require_developer(config), resolve_user)

        @app.get("/profile")
        async def profile(user: User = Depends(get_current_user)):
            return user
    """
    from fastapi import Depends

    async def dependency(
        claims: TokenClaims = Depends(claims_dependency),
    ) -> UserT:
        return await resolver(claims)

    return dependency


def create_db_resolver(
    user_model: type[UserT],
    id_field: str = "id",
) -> Callable[..., UserT]:
    """
    Create a simple database resolver for SQLAlchemy-style models.

    This is a convenience factory for common resolution patterns.
    The returned resolver uses FastAPI's Depends system for the db session.

    Args:
        user_model: The SQLAlchemy model class (e.g., User)
        id_field: The field on the model that matches claims.sub (default: "id")

    Returns:
        A resolver function that can be used with with_user_resolver

    Example:
        from myapp.models import User
        from myapp.database import get_db

        # Create resolver
        resolve_user = create_db_resolver(User)

        # Use in dependency
        async def get_current_user(
            claims: TokenClaims = Depends(require_developer(config)),
            db: Session = Depends(get_db),
        ) -> User:
            user = db.query(User).filter(User.id == claims.sub).first()
            if not user:
                raise HTTPException(401, "User not found")
            return user

    Note: This returns a template function. You'll need to adapt it to your
    specific database session pattern.
    """
    from fastapi import HTTPException

    async def resolver(claims: TokenClaims, db: Any) -> UserT:
        query_filter = {id_field: claims.sub}
        user = db.query(user_model).filter_by(**query_filter).first()
        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

    return resolver
