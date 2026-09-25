from __future__ import annotations

import re
from collections.abc import Iterable

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}


def redact_secrets(text: str, secret_values: Iterable[str] = ()) -> str:
    redacted = text
    for secret in sorted((value for value in secret_values if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    redacted = re.sub(
        r"(?im)^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization):.*$",
        lambda match: f"{match.group(1)}: [REDACTED]",
        redacted,
    )
    return redacted
