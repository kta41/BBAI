from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuthProfile:
    name: str
    auth_type: str
    secret_ref: str
    expires_at: datetime | None = None
    role: str = "custom"


@dataclass(frozen=True)
class AuthContext:
    profile: AuthProfile
    headers: dict[str, str]
    secret_values: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"{self.profile.name} ({self.profile.auth_type})"
