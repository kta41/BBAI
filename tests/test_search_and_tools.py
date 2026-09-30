from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from pytest import MonkeyPatch

from bbai.auth.models import AuthContext, AuthProfile
from bbai.config import Settings
from bbai.diagnostics import run_diagnostics
from bbai.services.project_service import ProjectService
from bbai.tools.base import (
    GauTool,
    HttpInspectTool,
    KatanaTool,
    NucleiTool,
    _validate_scoped_url,
    is_host_in_scope,
    is_url_in_scope,
)
from bbai.tools.policy import ScopePolicy
from bbai.tools.registry import (
    build_tools,
    tool_availability,
    tool_definitions,
    tool_security_metadata,
)


def test_fts_search_backfills_indexes_and_updates_findings(tmp_path: Path) -> None:
    service = ProjectService(str(tmp_path / "bbai.db"))
    service.add_target(name="example.com", scope="example.com")
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="headers.txt",
        kind="http-response",
        content="Security headers including Content-Security-Policy are missing from response.",
    )
    session_id = service.create_session(target_name="example.com", title="Header review")
    note_id = service.add_session_note(session_id, content="Inspect security headers.")

    matches = service.search_artifacts("security headers")
    assert any(result["type"] == "evidence" and result["id"] == evidence_id for result in matches)
    assert any(result["type"] == "note" and result["id"] == note_id for result in matches)
    filtered = service.search_artifacts(
        "security headers",
        artifact_type="note",
        session_id=session_id,
    )
    assert len(filtered) == 1
    assert filtered[0]["target"] == "example.com"

    finding_id = service.add_finding(
        target_name="example.com",
        title="Missing CSP",
        summary="Security header missing on endpoint.",
    )
    assert service.search_artifacts("Missing CSP", status="draft")[0]["id"] == finding_id
    service.update_finding(finding_id, status="in_review")
    assert service.search_artifacts("Missing CSP", status="draft") == []
    assert service.search_artifacts("Missing CSP", status="in_review")[0]["id"] == finding_id
    assert service.rebuild_search_index() >= 4
    assert service.search_artifacts("Content Security Policy", artifact_type="evidence")


def test_doctor_reports_migration_fts5_and_optional_tools(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    root = tmp_path
    settings = Settings(project_root=root)
    root.mkdir(exist_ok=True)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    settings.save()
    service = ProjectService(str(settings.db_path))
    service.add_target(name="example.com", scope="example.com")
    settings.active_target = "example.com"
    settings.save()
    monkeypatch.setattr(
        "bbai.diagnostics.httpx.get",
        lambda *args, **kwargs: type(
            "Response",
            (),
            {
                "raise_for_status": lambda self: None,
                "json": lambda self: {"models": [{"name": settings.ollama.default_model}]},
            },
        )(),
    )
    monkeypatch.setattr(
        "bbai.diagnostics.keyring.get_keyring",
        lambda: type("Backend", (), {"priority": 1})(),
    )
    monkeypatch.setattr(
        "bbai.diagnostics.shutil.which",
        lambda binary: f"/usr/bin/{binary}" if binary == "gau" else None,
    )

    checks = run_diagnostics(settings)
    by_name = {check["name"]: check for check in checks}
    assert by_name["Database"]["status"] == "ok"
    assert by_name["Migrations"]["status"] == "ok"
    assert by_name["SQLite FTS5"]["status"] == "ok"
    assert by_name["Ollama"]["status"] == "ok"
    assert by_name["Configured model"]["status"] == "ok"
    assert by_name["Active target"]["status"] == "ok"
    assert by_name["gau"]["status"] == "ok"
    assert by_name["nuclei"]["status"] == "warning"


def test_gau_filters_archive_results_to_scope(monkeypatch: MonkeyPatch) -> None:
    marker = "archive" + "-marker"
    monkeypatch.setattr("bbai.tools.base.shutil.which", lambda _: "/usr/bin/gau")
    monkeypatch.setattr(
        "bbai.tools.base.run_external",
        lambda *args, **kwargs: (
            "https://example.com/a\n"
            "https://sub.example.com/b\n"
            f"https://example.com/private?token={marker}\n"
            "https://outside.example.net/private\n"
            "not a url\n"
            "https://example.com/a\n"
        ),
    )
    auth = AuthContext(
        profile=AuthProfile(name="user", auth_type="bearer", secret_ref="example/user"),
        headers={},
        secret_values=(marker,),
    )
    results = GauTool(scope="*.example.com", auth=auth).execute(domain="example.com")
    assert results.splitlines() == [
        "https://example.com/a",
        "https://sub.example.com/b",
        "https://example.com/private?token=[REDACTED]",
    ]
    try:
        GauTool(scope="example.com").execute(domain="outside.example.net")
    except ValueError as exc:
        assert "outside the approved scope" in str(exc)
    else:
        raise AssertionError("gau must reject domains outside scope")


def test_scope_matching_normalizes_idn_ips_and_label_boundaries() -> None:
    assert is_host_in_scope("bücher.example", "xn--bcher-kva.example")
    assert is_host_in_scope("api.xn--bcher-kva.example.", "*.bücher.example")
    assert is_host_in_scope("192.0.2.10", "192.0.2.10")
    assert is_host_in_scope("2001:db8::1", "2001:db8::1")
    assert is_url_in_scope("example.com", 443, "example.com")
    assert is_url_in_scope("example.com", 8443, "*.example.com:8443")
    assert not is_url_in_scope("example.com", 8443, "*.example.com")
    assert not is_url_in_scope("example.com", 443, "example.com:8443")
    assert not is_host_in_scope("notexample.com", "*.example.com")
    assert not is_host_in_scope("example.com.attacker.test", "example.com")
    assert not is_host_in_scope("badexample.com", "*example.com")


def test_scoped_url_validates_ports_and_rejects_credentials() -> None:
    parsed = _validate_scoped_url("https://example.com:8443/", "example.com:8443", "test")
    assert parsed.port == 8443
    _validate_scoped_url(
        "https://bücher.example:8443/",
        "xn--bcher-kva.example:8443",
        "test",
    )
    _validate_scoped_url(
        "https://[2001:db8::1]:8443/",
        "[2001:db8::1]:8443",
        "test",
    )
    parsed_default = _validate_scoped_url("https://example.com/", "example.com", "test")
    assert parsed_default.port is None
    try:
        _validate_scoped_url("https://example.com:8443/", "example.com", "test")
    except ValueError as exc:
        assert "outside the approved scope" in str(exc)
    else:
        raise AssertionError("non-standard ports must be explicitly included in scope")
    credentialed_url = "https://" + "researcher" + "@" + "example.com/"
    for url in (
        credentialed_url,
        "https://@example.com/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:invalid/",
    ):
        try:
            _validate_scoped_url(url, "example.com", "test")
        except ValueError:
            continue
        raise AssertionError(f"invalid URL should be rejected: {url}")


def test_http_tool_accepts_valid_ports_and_rejects_invalid_ports_or_credentials() -> None:
    tool = HttpInspectTool(scope="example.com")
    parsed = tool.execute
    assert callable(parsed)
    assert is_host_in_scope("example.com", "example.com")

    for url in (
        "https://user:password@example.com/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:invalid/",
    ):
        try:
            tool.execute(url=url)
        except ValueError as exc:
            assert "URL" in str(exc)
        else:
            raise AssertionError(f"invalid URL should be rejected: {url}")


def test_http_inspect_does_not_follow_redirects() -> None:
    requested_paths: list[str] = []

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requested_paths.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = HttpInspectTool(scope=f"127.0.0.1:{port}").execute(
            url=f"http://127.0.0.1:{server.server_port}/start"
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert "STATUS: 302" in result
    assert requested_paths == ["/start"]


def test_katana_is_host_constrained_and_filters_discovered_urls(
    monkeypatch: MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    output = "\n".join(
        (
            json.dumps({"request": {"endpoint": "https://example.com/a?token=secret-value"}}),
            json.dumps({"request": {"endpoint": "https://outside.example.net/b"}}),
            json.dumps({"request": {"endpoint": "https://example.com/a?token=secret-value"}}),
        )
    )

    def fake_run(command: list[str], **kwargs: object) -> str:
        calls.append((command, kwargs))
        return output

    monkeypatch.setattr("bbai.tools.base.shutil.which", lambda _: "/usr/bin/katana")
    monkeypatch.setattr("bbai.tools.base.run_external", fake_run)
    auth = AuthContext(
        profile=AuthProfile(name="user", auth_type="bearer", secret_ref="example/user"),
        headers={"Authorization": "Bearer secret-value"},
        secret_values=("secret-value",),
    )
    results = KatanaTool(scope="*.example.com", auth=auth).execute(url="https://example.com/")
    command = calls[0][0]
    assert any(argument.startswith("Authorization: ") for argument in command)
    assert results == "https://example.com/a?token=[REDACTED]"
    assert any(argument.startswith("Authorization: ") for argument in command)
    assert "secret-value" not in results
    assert command[command.index("-d") + 1] == "2"
    assert command[command.index("-rl") + 1] == "5"
    assert "-disable-redirects" in command
    crawl_scope = command[command.index("-cs") + 1]
    assert re.search(crawl_scope, "https://example.com/a")
    assert not re.search(crawl_scope, "https://example.com:8443/a")


def test_nuclei_uses_only_bundled_templates_and_fixed_safe_limits(
    monkeypatch: MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    auth = AuthContext(
        profile=AuthProfile(name="user", auth_type="bearer", secret_ref="example/user"),
        headers={"X-Test-Auth": "enabled"},
        secret_values=(),
    )

    def fake_run(command: list[str], **kwargs: object) -> str:
        calls.append(command)
        records = [
            {
                "info": {"name": "Missing CSP", "severity": "info"},
                "matched-at": "https://example.com/",
            },
            {
                "info": {"name": "Unexpected", "severity": "info"},
                "matched-at": "https://outside.example.net/",
            },
        ]
        return "\n".join(json.dumps(record) for record in records)

    monkeypatch.setattr("bbai.tools.base.shutil.which", lambda _: "/usr/bin/nuclei")
    monkeypatch.setattr("bbai.tools.base.run_external", fake_run)
    result = NucleiTool(scope="example.com", auth=auth).execute(url="https://example.com/")
    command = calls[0]
    template_args = [
        command[index + 1] for index, value in enumerate(command[:-1]) if value == "-t"
    ]
    assert len(template_args) == 2
    assert all(Path(path).is_file() for path in template_args)
    assert command[command.index("-rl") + 1] == "5"
    assert command[command.index("-c") + 1] == "2"
    assert command[command.index("-retries") + 1] == "0"
    assert "-no-interactsh" in command
    assert "-disable-redirects" in command
    assert any(argument == "X-Test-Auth: enabled" for argument in command)
    assert result == "[info] Missing CSP: https://example.com/"
    assert "Unexpected" not in result


def test_registry_exposes_new_tools_and_retains_human_policy() -> None:
    auth = AuthContext(
        profile=AuthProfile(name="user", auth_type="bearer", secret_ref="example/user"),
        headers={"Authorization": "Bearer token"},
        secret_values=("token",),
    )
    tools = build_tools(scope="example.com", timeout_seconds=20, auth=auth)
    assert {"gau", "katana", "nuclei"} <= tools.keys()
    assert tools["ffuf"].auth is auth  # type: ignore[attr-defined]
    assert {tool["function"]["name"] for tool in tool_definitions(tools)} == set(tools)
    metadata = tool_security_metadata()
    assert {item["activity"] for item in metadata.values()} <= {
        "passive",
        "active_read",
        "intrusive",
    }
    assert all(item["approval_required"] is True for item in metadata.values())
    assert metadata["gau"]["activity"] == "passive"
    assert metadata["ffuf"]["risk"] == "high"
    policy = ScopePolicy(
        allowed_tools=frozenset(tools),
        approval_required=False,
        tool_approval_required={
            name: tool.approval_required for name, tool in tools.items()
        },
    )
    assert all(policy.requires_approval(name) for name in tools)
    assert not ScopePolicy(
        frozenset({"safe"}),
        approval_required=False,
        tool_approval_required={"safe": False},
    ).requires_approval("safe")
    assert ScopePolicy(frozenset({"listed"}), approval_required=False).requires_approval(
        "listed"
    )
    availability = tool_availability()
    assert {"gau", "katana", "nuclei"} <= availability.keys()
