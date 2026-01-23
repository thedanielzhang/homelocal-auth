"""
Token claims model.
"""

from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class TokenClaims:
    """
    Parsed and validated JWT claims.

    Attributes:
        sub: Subject (user ID)
        roles: List of role names from the 'roles' claim
        exp: Expiration timestamp (Unix epoch)
        raw_payload: Full decoded JWT payload for accessing custom claims

    Example:
        claims = TokenClaims(
            sub="user-123",
            roles=["default", "dev"],
            exp=1737500000,
            raw_payload={"sub": "user-123", "roles": ["default", "dev"], ...}
        )

        if claims.has_role("admin"):
            # admin-only logic
    """

    sub: str
    roles: list[str]
    exp: int
    raw_payload: dict[str, Any]

    def has_role(self, role: str) -> bool:
        """Check if the token has a specific role."""
        return role in self.roles

    def has_any_role(self, role_names: Sequence[str]) -> bool:
        """Check if the token has any of the specified roles."""
        return bool(set(self.roles).intersection(role_names))

    def has_all_roles(self, role_names: Sequence[str]) -> bool:
        """Check if the token has all of the specified roles."""
        return all(role in self.roles for role in role_names)

    @property
    def is_admin(self) -> bool:
        """Check if the token has 'admin' role."""
        return "admin" in self.roles

    @property
    def is_developer(self) -> bool:
        """Check if the token has 'dev' role."""
        return "dev" in self.roles

    @property
    def email(self) -> str | None:
        """Get email from payload if present."""
        return self.raw_payload.get("email")

    @property
    def name(self) -> str | None:
        """Get name from payload if present."""
        return self.raw_payload.get("name")

    def get_claim(self, key: str, default: Any = None) -> Any:
        """Get a custom claim from the raw payload."""
        return self.raw_payload.get(key, default)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "TokenClaims":
        """
        Create TokenClaims from a decoded JWT payload.

        Args:
            payload: Decoded JWT payload dictionary

        Returns:
            TokenClaims instance

        Raises:
            ValueError: If required claims are missing
        """
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Token missing required 'sub' claim")

        exp = payload.get("exp")
        if exp is None:
            raise ValueError("Token missing required 'exp' claim")

        # Extract roles, defaulting to empty list
        roles_raw = payload.get("roles", [])
        if isinstance(roles_raw, list):
            roles = [str(r) for r in roles_raw]
        else:
            roles = []

        return cls(
            sub=str(sub),
            roles=roles,
            exp=int(exp),
            raw_payload=payload,
        )
