from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from contextlib import ExitStack
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, ClassVar, Literal
from urllib.parse import ParseResult, urlparse

import httpx

from bbai.auth.models import AuthContext
from bbai.auth.redaction import redact_secrets

ToolActivity = Literal["passive", "active_read", "intrusive"]
ToolRisk = Literal["low", "medium", "high"]


class Tool(ABC):
    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[dict[str, Any]]
    activity: ClassVar[ToolActivity] = "active_read"
    risk_level: ClassVar[ToolRisk] = "high"
    approval_required: ClassVar[bool] = True
    permission: ClassVar[str] = "network"
    timeout_limit_seconds: ClassVar[int] = 60
    output_limit_chars: ClassVar[int] = 20000

    @abstractmethod
    def execute(self, **kwargs: Any) -> str:
        raise NotImplementedError


class NullTool(Tool):
    name: ClassVar[str] = "null"
    description: ClassVar[str] = "Placeholder tool used for scaffolding."
    input_schema: ClassVar[dict[str, Any]] = {"type": "object", "properties": {}}
    activity: ClassVar[ToolActivity] = "passive"
    risk_level: ClassVar[ToolRisk] = "low"
    approval_required: ClassVar[bool] = False
    permission: ClassVar[str] = "none"

    def execute(self, **kwargs: Any) -> str:
        return "Tool scaffolding is active. No dangerous execution is enabled by default."


class HttpInspectTool(Tool):
    name: ClassVar[str] = "http_inspect"
    description: ClassVar[str] = (
        "Perform one read-only HTTP GET request against a host in the approved target scope. "
        "Do not use this for state-changing actions."
    )
    activity: ClassVar[ToolActivity] = "active_read"
    risk_level: ClassVar[ToolRisk] = "medium"
    permission: ClassVar[str] = "scoped HTTP GET"
    timeout_limit_seconds: ClassVar[int] = 15
    output_limit_chars: ClassVar[int] = 12000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Absolute http:// or https:// URL to inspect.",
            },
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
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_body_chars = min(max(max_body_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url = kwargs.get("url")
        if not isinstance(url, str):
            raise TypeError("http_inspect requires a string URL")
        _validate_scoped_url(url, self.scope, self.name)

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={
                "User-Agent": "bbai/0.1 http_inspect",
                **(self.auth.headers if self.auth else {}),
            },
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

class HttpHeadersTool(HttpInspectTool):
    name: ClassVar[str] = "http_headers"
    description: ClassVar[str] = (
        "Perform one read-only HTTP GET request and return only response headers "
        "for a host in the approved target scope."
    )
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Absolute http:// or https:// URL to inspect.",
            },
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
    activity: ClassVar[ToolActivity] = "passive"
    risk_level: ClassVar[ToolRisk] = "low"
    permission: ClassVar[str] = "passive subdomain enumeration"
    timeout_limit_seconds: ClassVar[int] = 60
    output_limit_chars: ClassVar[int] = 20000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "In-scope root domain to enumerate."},
        },
        "required": ["domain"],
    }

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 60,
        max_output_chars: int = 20000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_output_chars = min(max(max_output_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        domain = kwargs.get("domain")
        if not isinstance(domain, str) or not domain or any(
            char in domain for char in "/@?#:"
        ):
            raise TypeError("subfinder requires a domain name")
        normalized_domain = _normalize_hostname(domain)
        if normalized_domain is None or not is_host_in_scope(normalized_domain, self.scope):
            raise ValueError(f"Host '{domain}' is outside the approved scope")
        if shutil.which("subfinder") is None:
            raise RuntimeError("subfinder is not installed or not available in PATH")
        return run_external(
            ["subfinder", "-d", normalized_domain, "-silent"],
            timeout_seconds=self.timeout_seconds,
            max_output_chars=self.max_output_chars,
        )


class FfufTool(Tool):
    name: ClassVar[str] = "ffuf"
    description: ClassVar[str] = (
        "Run bounded web content discovery against an in-scope URL containing the FUZZ "
        "marker using the installed ffuf binary."
    )
    activity: ClassVar[ToolActivity] = "active_read"
    risk_level: ClassVar[ToolRisk] = "high"
    permission: ClassVar[str] = "bounded HTTP requests with a local wordlist"
    timeout_limit_seconds: ClassVar[int] = 60
    output_limit_chars: ClassVar[int] = 30000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "In-scope URL containing FUZZ."},
            "wordlist": {"type": "string", "description": "Existing local wordlist path."},
        },
        "required": ["url", "wordlist"],
    }

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 60,
        max_output_chars: int = 30000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_output_chars = min(max(max_output_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url = kwargs.get("url")
        wordlist = kwargs.get("wordlist")
        if not isinstance(url, str) or "FUZZ" not in url:
            raise ValueError("ffuf requires a URL containing the FUZZ marker")
        if not isinstance(wordlist, str):
            raise TypeError("ffuf requires a wordlist path")
        _validate_scoped_url(
            url.replace("FUZZ", "scope-validation"),
            self.scope,
            "ffuf",
        )
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


class GauTool(Tool):
    name: ClassVar[str] = "gau"
    description: ClassVar[str] = (
        "Passively retrieve archived URLs for an in-scope domain. Returned URLs are "
        "filtered to the approved scope and are not probed."
    )
    activity: ClassVar[ToolActivity] = "passive"
    risk_level: ClassVar[ToolRisk] = "low"
    permission: ClassVar[str] = "passive archive lookup"
    timeout_limit_seconds: ClassVar[int] = 120
    output_limit_chars: ClassVar[int] = 20000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "In-scope domain to query archives for."},
        },
        "required": ["domain"],
    }

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 60,
        max_output_chars: int = 20000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_output_chars = min(max(max_output_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        domain = kwargs.get("domain")
        if not isinstance(domain, str) or not domain or any(char in domain for char in "/@?#"):
            raise ValueError("gau requires a bare domain name")
        parsed = urlparse(f"https://{domain}")
        try:
            has_port = parsed.port is not None
        except ValueError as exc:
            raise ValueError("gau requires a bare domain name") from exc
        normalized_host = _normalize_hostname(parsed.hostname or "")
        if (
            not normalized_host
            or has_port
            or parsed.username
            or parsed.password
            or not is_host_in_scope(normalized_host, self.scope)
        ):
            raise ValueError(f"Host '{domain}' is outside the approved scope")
        if shutil.which("gau") is None:
            raise RuntimeError("gau is not installed or not available in PATH")
        output = run_external(
            ["gau", "--subs", normalized_host],
            timeout_seconds=self.timeout_seconds,
            max_output_chars=self.max_output_chars,
        )
        in_scope_urls: list[str] = []
        seen: set[str] = set()
        for line in output.splitlines():
            candidate = line.strip()
            try:
                _validate_scoped_url(candidate, self.scope, "gau")
            except ValueError:
                continue
            if candidate not in seen:
                seen.add(candidate)
                in_scope_urls.append(candidate)
        result = "\n".join(in_scope_urls) or "No archived URLs in the approved scope."
        return redact_secrets(result, self.auth.secret_values if self.auth else ())


class KatanaTool(Tool):
    name: ClassVar[str] = "katana"
    description: ClassVar[str] = (
        "Crawl one in-scope host using shallow, rate-limited settings. The crawl is "
        "restricted to the exact starting hostname and does not submit forms."
    )
    activity: ClassVar[ToolActivity] = "active_read"
    risk_level: ClassVar[ToolRisk] = "high"
    permission: ClassVar[str] = "shallow crawl of the starting host"
    timeout_limit_seconds: ClassVar[int] = 120
    output_limit_chars: ClassVar[int] = 20000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute in-scope HTTP(S) URL to crawl."},
        },
        "required": ["url"],
    }

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 60,
        max_output_chars: int = 20000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_output_chars = min(max(max_output_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url_value = kwargs.get("url")
        if not isinstance(url_value, str):
            raise TypeError("katana requires a URL")
        parsed = _validate_scoped_url(url_value, self.scope, "katana")
        hostname = _normalize_hostname(parsed.hostname or "")
        if hostname is None:
            raise RuntimeError("validated katana URL has no hostname")
        if shutil.which("katana") is None:
            raise RuntimeError("katana is not installed or not available in PATH")
        crawl_scope = _katana_scope_regex(hostname, self.scope)
        command = [
            "katana",
            "-u",
            url_value,
            "-jsonl",
            "-silent",
            "-d",
            "2",
            "-c",
            "2",
            "-rl",
            "5",
            "-timeout",
            "10",
            "-retry",
            "0",
            "-disable-redirects",
            "-cs",
            crawl_scope,
        ]
        if self.auth is not None:
            for name, value in self.auth.headers.items():
                command.extend(["-H", f"{name}: {value}"])
        output = run_external(
            command,
            timeout_seconds=self.timeout_seconds + 5,
            max_output_chars=self.max_output_chars,
        )
        urls: list[str] = []
        seen: set[str] = set()
        for line in output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("katana returned an invalid JSONL record") from exc
            if not isinstance(record, dict):
                continue
            request = record.get("request")
            candidate = record.get("url")
            if not isinstance(candidate, str) and isinstance(request, dict):
                candidate = request.get("endpoint")
            if not isinstance(candidate, str):
                continue
            try:
                discovered = _validate_scoped_url(candidate, self.scope, "katana")
            except ValueError:
                continue
            discovered_hostname = discovered.hostname
            if (
                discovered_hostname
                and _normalize_hostname(discovered_hostname) == _normalize_hostname(hostname)
                and candidate not in seen
            ):
                urls.append(candidate)
                seen.add(candidate)
        result = "\n".join(urls) or "No in-scope URLs discovered."
        return redact_secrets(result, self.auth.secret_values if self.auth else ())


class NucleiTool(Tool):
    name: ClassVar[str] = "nuclei"
    description: ClassVar[str] = (
        "Run only bbai-bundled, low-impact HTTP security-header checks against one "
        "in-scope URL. Templates, rate, concurrency, and retries are fixed by bbai."
    )
    activity: ClassVar[ToolActivity] = "active_read"
    risk_level: ClassVar[ToolRisk] = "high"
    permission: ClassVar[str] = "bundled low-impact HTTP header checks"
    timeout_limit_seconds: ClassVar[int] = 60
    output_limit_chars: ClassVar[int] = 20000
    input_schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Absolute in-scope HTTP(S) URL to check."},
        },
        "required": ["url"],
    }
    TEMPLATE_NAMES: ClassVar[tuple[str, ...]] = (
        "missing-content-security-policy.yaml",
        "missing-x-content-type-options.yaml",
    )

    def __init__(
        self,
        *,
        scope: str,
        timeout_seconds: int = 60,
        max_output_chars: int = 20000,
        auth: AuthContext | None = None,
    ) -> None:
        self.scope = scope
        self.timeout_seconds = min(max(timeout_seconds, 1), self.timeout_limit_seconds)
        self.max_output_chars = min(max(max_output_chars, 1), self.output_limit_chars)
        self.auth = auth

    def execute(self, **kwargs: Any) -> str:
        url = kwargs.get("url")
        if not isinstance(url, str):
            raise TypeError("nuclei requires a URL")
        _validate_scoped_url(url, self.scope, "nuclei")
        if shutil.which("nuclei") is None:
            raise RuntimeError("nuclei is not installed or not available in PATH")
        template_root = files("bbai.tools").joinpath("nuclei_templates")
        with ExitStack() as stack:
            template_paths = [
                str(stack.enter_context(as_file(template_root.joinpath(name))))
                for name in self.TEMPLATE_NAMES
            ]
            command = [
                "nuclei",
                "-u",
                url,
                "-jsonl",
                "-silent",
                "-no-interactsh",
                "-disable-redirects",
                "-duc",
                "-rl",
                "5",
                "-c",
                "2",
                "-timeout",
                "5",
                "-retries",
                "0",
            ]
            for template in template_paths:
                command.extend(["-t", template])
            if self.auth is not None:
                for name, value in self.auth.headers.items():
                    command.extend(["-H", f"{name}: {value}"])
            output = run_external(
                command,
                timeout_seconds=self.timeout_seconds + 5,
                max_output_chars=self.max_output_chars,
            )
        results: list[str] = []
        for line in output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("nuclei returned an invalid JSONL record") from exc
            if isinstance(record, dict):
                info = record.get("info")
                name = info.get("name", "unnamed check") if isinstance(info, dict) else "check"
                matched = record.get("matched-at", url)
                severity = info.get("severity", "info") if isinstance(info, dict) else "info"
                if not isinstance(matched, str):
                    continue
                try:
                    matched_url = _validate_scoped_url(matched, self.scope, "nuclei")
                except ValueError:
                    continue
                target_url = urlparse(url)
                if (
                    not matched_url.hostname
                    or not target_url.hostname
                    or _normalize_hostname(matched_url.hostname)
                    != _normalize_hostname(target_url.hostname)
                ):
                    continue
                results.append(f"[{severity}] {name}: {matched}")
        output_text = "\n".join(results) or "No findings from the bundled safe checks."
        return redact_secrets(
            output_text,
            self.auth.secret_values if self.auth else (),
        )


def _validate_scoped_url(url: str, scope: str, tool_name: str) -> ParseResult:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{tool_name} requires a valid HTTP(S) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or "@" in parsed.netloc
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(f"{tool_name} requires an absolute HTTP(S) URL without credentials")
    effective_port = port or (443 if parsed.scheme == "https" else 80)
    if not is_url_in_scope(hostname, effective_port, scope):
        raise ValueError(
            f"Host and port '{hostname}:{effective_port}' are outside the approved scope"
        )
    return parsed


def is_host_in_scope(hostname: str, scope: str) -> bool:
    normalized = _normalize_hostname(hostname)
    if normalized is None:
        return False
    for raw_rule in scope.replace(",", "\n").splitlines():
        rule = raw_rule.strip().lower()
        if not rule:
            continue
        normalized_rule, _port = _parse_scope_rule(rule)
        if normalized_rule is None:
            continue
        if _host_matches_scope(normalized, normalized_rule):
            return True
    return False


def is_url_in_scope(hostname: str, port: int, scope: str) -> bool:
    normalized = _normalize_hostname(hostname)
    if normalized is None or not 1 <= port <= 65535:
        return False
    return port in _allowed_ports_for_host(normalized, scope)


def _allowed_ports_for_host(hostname: str, scope: str) -> set[int]:
    allowed: set[int] = set()
    for raw_rule in scope.replace(",", "\n").splitlines():
        rule = raw_rule.strip().lower()
        if not rule:
            continue
        normalized_rule, allowed_port = _parse_scope_rule(rule)
        if normalized_rule is None or not _host_matches_scope(hostname, normalized_rule):
            continue
        if allowed_port is None:
            allowed.update({80, 443})
        else:
            allowed.add(allowed_port)
    return allowed


def _katana_scope_regex(hostname: str, scope: str) -> str:
    host_pattern = f"[{hostname}]" if ":" in hostname else hostname
    allowed_ports = _allowed_ports_for_host(hostname, scope)
    prefixes: list[str] = []
    for scheme, default_port in (("http", 80), ("https", 443)):
        for port in sorted(allowed_ports):
            authority = f"{scheme}://{re.escape(host_pattern)}"
            if port == default_port:
                prefixes.append(f"{authority}(?::{port})?")
            else:
                prefixes.append(f"{authority}:{port}")
    if not prefixes:
        return r"(?!)"
    return rf"^(?:{'|'.join(prefixes)})(?:[/?#]|$)"


def _host_matches_scope(hostname: str, scope_hostname: str) -> bool:
    return hostname == scope_hostname or hostname.endswith(f".{scope_hostname}")


def _parse_scope_rule(rule: str) -> tuple[str | None, int | None]:
    wildcard = rule.startswith("*.")
    candidate = rule.removeprefix("*.") if wildcard else rule
    if "*" in candidate:
        return None, None

    port: int | None = None
    if candidate.startswith("["):
        closing_bracket = candidate.find("]")
        if closing_bracket < 0:
            return None, None
        host = candidate[1:closing_bracket]
        suffix = candidate[closing_bracket + 1 :]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:].isdigit():
                return None, None
            port = int(suffix[1:])
    else:
        try:
            ipaddress.ip_address(candidate)
            host = candidate
        except ValueError:
            if ":" in candidate:
                host, raw_port = candidate.rsplit(":", 1)
                if not raw_port.isdigit():
                    return None, None
                port = int(raw_port)
            else:
                host = candidate
    if port is not None and not 1 <= port <= 65535:
        return None, None
    normalized = _normalize_hostname(host)
    return normalized, port


def _normalize_hostname(hostname: str) -> str | None:
    candidate = hostname.strip().rstrip(".")
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        if ":" in candidate or any(char.isspace() for char in candidate):
            return None
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    labels = normalized.split(".")
    if len(normalized) > 253 or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return normalized


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
    output = (
        completed.stdout + ("\nSTDERR:\n" + completed.stderr if completed.stderr else "")
    ).strip()
    if completed.returncode != 0:
        raise RuntimeError(
            f"Tool exited with code {completed.returncode}:\n{output[:max_output_chars]}"
        )
    return output[:max_output_chars]
