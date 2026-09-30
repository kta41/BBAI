from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

import httpx

from bbai.auth.models import AuthContext
from bbai.auth.redaction import redact_secrets


class Tool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[dict[str, Any]]

    @abstractmethod
    def execute(self, **kwargs: Any) -> str:
        raise NotImplementedError


class NullTool(Tool):
    name: ClassVar[str] = "null"
    description: ClassVar[str] = "Placeholder tool used for scaffolding."
    input_schema: ClassVar[dict[str, Any]] = {"type": "object", "properties": {}}

    def execute(self, **kwargs: Any) -> str:
        return "Tool scaffolding is active. No dangerous execution is enabled by default."


class HttpInspectTool(Tool):
    name: ClassVar[str] = "http_inspect"
    description: ClassVar[str] = (
        "Perform one read-only HTTP GET request against a host in the approved target scope. "
        "Do not use this for state-changing actions."
    )
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute http:// or https:// URL to inspect."},
        },
        "required": ["url"],
    }

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 15,
        max_body_chars: int = 12000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.max_body_chars = max_body_chars
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url = kwargs.get("url")
        if not isinstance(url, str):
            raise TypeError("http_inspect requires a string URL")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Only absolute http:// or https:// URLs are allowed")
        if not self._is_in_scope(parsed.hostname):
            raise ValueError(f"Host '{parsed.hostname}' is outside the approved scope")

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "bbai/0.1 http_inspect", **(self.auth.headers if self.auth else {})},
        ) as client:
            response = client.get(url)

        body = response.text[: self.max_body_chars]
        return redact_secrets(
            f"URL: {response.url}\n"
            f"STATUS: {response.status_code}\n"
            f"HEADERS: {dict(response.headers)}\n"
            f"BODY_TRUNCATED: {len(response.text) > self.max_body_chars}\n"
            f"BODY:\n{body}",
            self.auth.secret_values if self.auth else (),
        )

    def _is_in_scope(self, hostname: str) -> bool:
        return is_host_in_scope(hostname, self.scope)


class HttpHeadersTool(HttpInspectTool):
    name: ClassVar[str] = "http_headers"
    description: ClassVar[str] = (
        "Perform one read-only HTTP GET request and return only response headers "
        "for a host in the approved target scope."
    )
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute http:// or https:// URL to inspect."},
        },
        "required": ["url"],
    }

    def execute(self, **kwargs: Any) -> str:
        result = super().execute(**kwargs)
        headers = result.split("HEADERS: ", 1)[-1].split("\nBODY_TRUNCATED:", 1)[0]
        return f"URL: {result.splitlines()[0].removeprefix('URL: ')}\nHEADERS: {headers}"


class SubfinderTool(Tool):
    name: ClassVar[str] = "subfinder"
    description: ClassVar[str] = (
        "Run passive subdomain enumeration for an approved in-scope domain using the "
        "installed subfinder binary. This does not perform active probing."
    )
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "In-scope root domain to enumerate."},
        },
        "required": ["domain"],
    }

    def __init__(
        self, *, scope: str, timeout_seconds: int = 60, max_output_chars: int = 20000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        domain = kwargs.get("domain")
        if not isinstance(domain, str) or not domain or "/" in domain:
            raise TypeError("subfinder requires a domain name")
        if not is_host_in_scope(domain, self.scope):
            raise ValueError(f"Host '{domain}' is outside the approved scope")
        if shutil.which("subfinder") is None:
            raise RuntimeError("subfinder is not installed or not available in PATH")
        return run_external(
            ["subfinder", "-d", domain, "-silent"],
            timeout_seconds=self.timeout_seconds,
            max_output_chars=self.max_output_chars,
        )


class FfufTool(Tool):
    name: ClassVar[str] = "ffuf"
    description: ClassVar[str] = (
        "Run bounded web content discovery against an in-scope URL containing the FUZZ "
        "marker using the installed ffuf binary."
    )
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "In-scope URL containing FUZZ."},
            "wordlist": {"type": "string", "description": "Existing local wordlist path."},
        },
        "required": ["url", "wordlist"],
    }

    def __init__(
        self, *, scope: str, timeout_seconds: int = 60, max_output_chars: int = 30000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url = kwargs.get("url")
        wordlist = kwargs.get("wordlist")
        if not isinstance(url, str) or "FUZZ" not in url:
            raise ValueError("ffuf requires a URL containing the FUZZ marker")
        if not isinstance(wordlist, str):
            raise TypeError("ffuf requires a wordlist path")
        parsed = urlparse(url.replace("FUZZ", "scope-validation"))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("ffuf requires an absolute http:// or https:// URL")
        if not is_host_in_scope(parsed.hostname, self.scope):
            raise ValueError(f"Host '{parsed.hostname}' is outside the approved scope")
        wordlist_path = Path(wordlist).expanduser().resolve()
        if not wordlist_path.is_file():
            raise ValueError(f"Wordlist not found: {wordlist_path}")
        if shutil.which("ffuf") is None:
            raise RuntimeError("ffuf is not installed or not available in PATH")
        command = [
            "ffuf",
            "-u",
            url,
            "-w",
            str(wordlist_path),
            "-json",
            "-noninteractive",
            "-s",
            "-maxtime",
            str(self.timeout_seconds),
        ]
        if self.auth is not None:
            for name, value in self.auth.headers.items():
                command.extend(["-H", f"{name}: {value}"])
        output = run_external(
            command,
            timeout_seconds=self.timeout_seconds + 5,
            max_output_chars=self.max_output_chars,
        )
        return redact_secrets(
            output,
            self.auth.secret_values if self.auth else (),
        )


def is_host_in_scope(hostname: str, scope: str) -> bool:
    rules = [rule.strip().lower() for rule in scope.replace(",", "\n").splitlines() if rule.strip()]
    normalized = hostname.lower().rstrip(".")
    return any(
        fnmatch(normalized, rule.lstrip("*."))
        or fnmatch(normalized, rule)
        or normalized.endswith(f".{rule.lstrip('*.')}")
        for rule in rules
    )


def run_external(command: list[str], *, timeout_seconds: int, max_output_chars: int) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Tool timed out after {timeout_seconds} seconds") from exc
    output = (completed.stdout + ("\nSTDERR:\n" + completed.stderr if completed.stderr else "")).strip()
    if completed.returncode != 0:
        raise RuntimeError(f"Tool exited with code {completed.returncode}:\n{output[:max_output_chars]}")
    return output[:max_output_chars]
