from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from bbai.auth.redaction import redact_secrets
from bbai.cli import app
from bbai.config import Settings
from bbai.llm.provider import OllamaProvider, ToolCall, ToolTurn
from bbai.services.project_service import ProjectService
from bbai.tools.base import HttpHeadersTool, is_host_in_scope

runner = CliRunner()


def test_redaction_removes_overlapping_secrets_and_sensitive_headers() -> None:
    value = (
        "token-long token\n"
        "Authorization: Bearer header-token\n"
        "sEt-CoOkIe: session=value\n"
    )

    redacted = redact_secrets(value, ("token", "token-long", "header-token"))

    assert "token-long" not in redacted
    assert "header-token" not in redacted
    assert "Authorization: [REDACTED]" in redacted
    assert "sEt-CoOkIe: [REDACTED]" in redacted


def test_scope_matching_respects_wildcard_boundaries() -> None:
    assert is_host_in_scope("example.com", "*.example.com")
    assert is_host_in_scope("api.example.com", "*.example.com")
    assert not is_host_in_scope("notexample.com", "*.example.com")
    assert not is_host_in_scope("example.com.attacker.test", "*.example.com")


def test_denied_tool_call_is_not_executed_and_is_persisted(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init", "--skip-dependency-setup"]).exit_code == 0
    assert runner.invoke(app, ["target", "add", "example.com", "--scope", "example.com"]).exit_code == 0
    assert runner.invoke(app, ["target", "use", "example.com"]).exit_code == 0

    call = ToolCall(
        identifier="call-denied",
        name="http_headers",
        arguments={"url": "https://example.com/"},
    )
    executions: list[dict[str, str]] = []
    tool = HttpHeadersTool(scope="example.com")

    def execute(**arguments: str) -> str:
        executions.append(arguments)
        return "Should not be reached."

    monkeypatch.setattr(tool, "execute", execute)
    monkeypatch.setattr("bbai.cli.build_tools", lambda **kwargs: {"http_headers": tool})

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
                text="The request was not authorized.",
                tool_calls=[],
                message={"role": "assistant", "content": "The request was not authorized."},
            )
        return ToolTurn(
            text="",
            tool_calls=[call],
            message={"role": "assistant", "content": ""},
        )

    monkeypatch.setattr(OllamaProvider, "chat_with_tools", fake_chat)
    result = runner.invoke(
        app,
        ["investigate", "Inspect headers"],
        input="n\n",
    )

    assert result.exit_code == 0, result.stdout
    assert executions == []
    service = ProjectService(str(Settings.load(tmp_path).db_path))
    execution = service.list_tool_executions(target_name="example.com")[0]
    assert execution["status"] == "denied"
    assert execution["approved"] is False
    assert "Human approval denied" in str(execution["error"])
    event = next(
        event
        for event in service.get_session(1)["events"]
        if event["type"] == "tool_result"
    )
    assert event["type"] == "tool_result"
    assert event["details"]["approved"] is False
