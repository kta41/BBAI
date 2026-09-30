from __future__ import annotations

import json
from pathlib import Path

from pytest import MonkeyPatch

from bbai.auth.models import AuthContext, AuthProfile
from bbai.config import Settings
from bbai.diagnostics import run_diagnostics
from bbai.services.project_service import ProjectService
from bbai.tools.base import GauTool, KatanaTool, NucleiTool
from bbai.tools.registry import build_tools, tool_availability, tool_definitions


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
    availability = tool_availability()
    assert {"gau", "katana", "nuclei"} <= availability.keys()
