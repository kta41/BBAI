from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Protocol

import keyring


class SecretStore(Protocol):
    def set(self, reference: str, payload: Mapping[str, str]) -> None: ...

    def get(self, reference: str) -> dict[str, str]: ...

    def delete(self, reference: str) -> None: ...


class KeyringSecretStore:
    service_name = "bbai"

    def set(self, reference: str, payload: Mapping[str, str]) -> None:
        keyring.set_password(self.service_name, reference, json.dumps(dict(payload)))

    def get(self, reference: str) -> dict[str, str]:
        raw = keyring.get_password(self.service_name, reference)
        if raw is None:
            raise ValueError(f"Secret '{reference}' was not found in the system keyring")
        value: Any = json.loads(raw)
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in value.items()
        ):
            raise ValueError("Stored authentication secret has an invalid format")
        return value

    def delete(self, reference: str) -> None:
        try:
            keyring.delete_password(self.service_name, reference)
        except keyring.errors.PasswordDeleteError:
            return
