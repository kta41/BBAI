from __future__ import annotations

import json
import os
from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from bbai.auth.store import KeyringSecretStore
from bbai.cli import app
from bbai.config import Settings
from bbai.llm.provider import OllamaProvider, ToolCall, ToolTurn
from bbai.services.project_service import ProjectService

runner = CliRunner()


def _setup_target(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init"]).exit_code == 0
    assert (
        runner.invoke(
            app,
            ["target", "add", "example.com", "--scope", "example.com"],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["target", "use", "example.com"]).exit_code == 0


def test_cli_finding_review_and_markdown_report(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    _setup_target(tmp_path, monkeypatch)
    evidence = tmp_path / "response.txt"
    evidence.write_text("X-Debug: enabled", encoding="utf-8")
    assert runner.invoke(app, ["evidence", "add", str(evidence)]).exit_code == 0
    assert (
        runner.invoke(
            app,
            ["observation", "add", "The debug header is exposed.", "--evidence", "1"],
        ).exit_code
        == 0
    )
    created = runner.invoke(
        app,
        [
            "finding",
            "create",
            "Debug disclosure",
            "The endpoint exposes debug metadata.",
            "--severity",
            "medium",
            "--evidence",
            "1",
            "--observation",
            "1",
            "--impact",
            "Internal details may be exposed.",
        ],
    )
    assert created.exit_code == 0, created.stdout
    assert "created as draft" in created.stdout
    assert runner.invoke(app, ["finding", "update", "1", "--status", "in_review"]).exit_code == 0
    reviewed = runner.invoke(
        app,
        ["finding", "review", "1", "--decision", "accepted", "--note", "Verified manually."],
    )
    assert reviewed.exit_code == 0
    report = runner.invoke(app, ["report", "1"])
    assert report.exit_code == 0, report.stdout
    assert "Debug disclosure" in report.stdout
    assert "X-Debug: enabled" in report.stdout
    assert "Verified manually." in report.stdout
    report_path = tmp_path / "private-report.md"
    written = runner.invoke(app, ["report", "1", "--output", str(report_path)])
    assert written.exit_code == 0, written.stdout
    if os.name == "posix":
        assert report_path.stat().st_mode & 0o777 == 0o600


def test_investigation_creates_and_resumes_persisted_session(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _setup_target(tmp_path, monkeypatch)

    async def fake_chat(
        self: OllamaProvider,
        messages: list[dict[str, object]],
        *,
        tools: list[dict[str, object]],
        model: str | None = None,
        system: str | None = None,
    ) -> ToolTurn:
        return ToolTurn(
            text="The target can now be reviewed manually.",
            tool_calls=[],
            message={"role": "assistant", "content": "The target can now be reviewed manually."},
        )

    monkeypatch.setattr(OllamaProvider, "chat_with_tools", fake_chat)
    investigation = runner.invoke(app, ["investigate", "Review the public landing page"])
    assert investigation.exit_code == 0, investigation.stdout
    assert "reviewed manually" in investigation.stdout

    sessions = runner.invoke(app, ["session", "list"])
    assert sessions.exit_code == 0
    assert "Review the public landing page" in sessions.stdout
    assert "(active)" in sessions.stdout

    shown = runner.invoke(app, ["session", "show"])
    assert shown.exit_code == 0
    assert "[question] Review the public landing page" in shown.stdout
    assert "[assistant] The target can now be reviewed manually." in shown.stdout

    note = runner.invoke(app, ["session", "note", "Recheck after deployment"])
    assert note.exit_code == 0
    paused = runner.invoke(app, ["session", "pause"])
    assert paused.exit_code == 0
    resumed = runner.invoke(app, ["session", "resume", "1"])
    assert resumed.exit_code == 0
    closed = runner.invoke(app, ["session", "close"])
    assert closed.exit_code == 0


def test_dry_run_tool_call_is_traced_to_session(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    _setup_target(tmp_path, monkeypatch)
    call = ToolCall(
        identifier="call-1",
        name="http_headers",
        arguments={"url": "https://example.com/"},
    )

    async def fake_chat(
        self: OllamaProvider,
        messages: list[dict[str, object]],
        *,
        tools: list[dict[str, object]],
        model: str | None = None,
        system: str | None = None,
    ) -> ToolTurn:
        if any(message.get("role") == "tool" for message in messages):
            return ToolTurn(
                text="No request was sent in dry-run mode.",
                tool_calls=[],
                message={"role": "assistant", "content": "No request was sent in dry-run mode."},
            )
        return ToolTurn(
            text="",
            tool_calls=[call],
            message={
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": call.identifier,
                        "function": {"name": call.name, "arguments": call.arguments},
                    }
                ],
            },
        )

    monkeypatch.setattr(OllamaProvider, "chat_with_tools", fake_chat)
    result = runner.invoke(app, ["investigate", "Inspect response headers", "--dry-run"])
    assert result.exit_code == 0, result.stdout
    executions = ProjectService(str(Settings.load(tmp_path).db_path)).list_tool_executions(
        target_name="example.com"
    )
    assert executions[0]["status"] == "dry_run"
    assert executions[0]["session_id"] == 1
    audit_log = tmp_path / ".bbai" / "audit.jsonl"
    audit_event = json.loads(audit_log.read_text(encoding="utf-8").splitlines()[0])
    assert audit_event["tool"] == "http_headers"
    assert audit_event["status"] == "dry_run"
    assert audit_event["approved"] is False
    assert "arguments" not in audit_event
    assert "https://example.com/" not in audit_log.read_text(encoding="utf-8")
    session = ProjectService(str(Settings.load(tmp_path).db_path)).get_session(1)
    assert [event["type"] for event in session["events"]] == [
        "question",
        "tool_call",
        "tool_result",
        "assistant",
    ]


def test_json_report_redacts_profile_secret(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    _setup_target(tmp_path, monkeypatch)
    service = ProjectService(str(Settings.load(tmp_path).db_path))
    service.add_auth_profile(
        target_name="example.com",
        name="normal-user",
        auth_type="bearer",
        secret_ref="example.com/normal-user",
    )
    evidence_id = service.add_evidence(
        target_name="example.com",
        source="response",
        kind="http-response",
        content=(
            "Captured value: report-secret-value\n"
            "Set-Cookie: raw-cookie-value\n"
            "Authorization: Bearer report-secret-value"
        ),
    )
    finding_id = service.add_finding(
        target_name="example.com",
        title="Token reflected",
        summary="A token appears in the response.",
        evidence_ids=[evidence_id],
    )
    service.update_finding(finding_id, status="in_review")
    service.review_finding(finding_id, decision="accepted")
    monkeypatch.setattr(
        KeyringSecretStore,
        "get",
        lambda self, reference: {"token": "report-secret-value"},
    )

    result = runner.invoke(app, ["report", "--format", "json"])
    assert result.exit_code == 0, result.stdout
    assert "report-secret-value" not in result.stdout
    assert "raw-cookie-value" not in result.stdout
    assert "[REDACTED]" in result.stdout
