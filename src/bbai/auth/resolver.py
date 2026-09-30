from __future__ import annotations

from datetime import UTC, datetime

from bbai.auth.models import AuthContext, AuthProfile
from bbai.auth.store import SecretStore


def resolve_auth(profile: AuthProfile, store: SecretStore) -> AuthContext:
    if profile.expires_at is not None:
        expiration = profile.expires_at
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=UTC)
        if expiration <= datetime.now(UTC):
            raise ValueError(f"Authentication profile '{profile.name}' has expired")
    if profile.role == "anonymous":
        return AuthContext(profile, {}, ())
    secret = store.get(profile.secret_ref)
    auth_type = profile.auth_type
    if auth_type == "bearer":
        token = secret.get("token")
        if not token:
            raise ValueError("Bearer profile is missing token")
        return AuthContext(profile, {"Authorization": f"Bearer {token}"}, (token,))
    if auth_type == "cookie":
        cookie = secret.get("cookie")
        if not cookie:
            raise ValueError("Cookie profile is missing cookie")
        return AuthContext(profile, {"Cookie": cookie}, (cookie,))
    if auth_type == "api_key":
        value = secret.get("value")
        header = secret.get("header", "X-API-Key")
        if not value:
            raise ValueError("API key profile is missing value")
        return AuthContext(profile, {header: value}, (value,))
    if auth_type == "headers":
        if not secret:
            raise ValueError("Headers profile is empty")
        return AuthContext(profile, dict(secret), tuple(secret.values()))
    raise ValueError(f"Unsupported authentication type '{auth_type}'")
