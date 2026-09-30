from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from bbai.cli import app
from bbai.config import Settings

runner = CliRunner()


def test_init_creates_project(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "Project initialized" in result.stdout
    assert "interactive terminal" in result.stdout


def test_init_setup_can_be_rerun_interactively(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init", "--skip-dependency-setup"])
    terminal = type("Terminal", (), {"isatty": lambda self: True})()
    monkeypatch.setattr("bbai.cli.sys.stdin", terminal)
    invoked = []
    monkeypatch.setattr("bbai.cli.run_setup_wizard", lambda settings: invoked.append(settings))
    result = runner.invoke(app, ["init", "--setup"])
    assert result.exit_code == 0
    assert len(invoked) == 1
    assert Settings.load(tmp_path).setup_wizard_completed


def test_target_add_and_list(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    result = runner.invoke(
        app,
        [
            "target",
            "add",
            "example.com",
            "--description",
            "Example target",
            "--scope",
            "example.com",
        ],
    )
    assert result.exit_code == 0
    assert "Target 'example.com' added" in result.stdout

    result = runner.invoke(app, ["target", "list"])
    assert result.exit_code == 0
    assert "example.com" in result.stdout


def test_target_use_and_evidence_list(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    runner.invoke(app, ["target", "add", "example.com", "--scope", "example.com"])
    result = runner.invoke(app, ["target", "use", "example.com"])
    assert result.exit_code == 0
    assert "Active target: example.com" in result.stdout

    evidence_path = tmp_path / "request.txt"
    evidence_path.write_text("GET /api/users HTTP/1.1", encoding="utf-8")
    result = runner.invoke(app, ["evidence", "add", str(evidence_path), "--kind", "http-request"])
    assert result.exit_code == 0
    assert "Evidence E-001 added" in result.stdout

    result = runner.invoke(app, ["evidence", "list"])
    assert result.exit_code == 0
    assert "http-request" in result.stdout


def test_observation_and_hypothesis_commands(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    runner.invoke(app, ["target", "add", "example.com", "--scope", "example.com"])
    runner.invoke(app, ["target", "use", "example.com"])

    result = runner.invoke(app, ["observation", "add", "The response exposes a debug header."])
    assert result.exit_code == 0
    assert "Observation O-001 added" in result.stdout

    result = runner.invoke(
        app,
        ["hypothesis", "add", "Debug information may be exposed.", "--confidence", "medium"],
    )
    assert result.exit_code == 0
    assert "Hypothesis H-001 added" in result.stdout

    result = runner.invoke(app, ["hypothesis", "update", "1", "--status", "supported"])
    assert result.exit_code == 0
    assert "updated" in result.stdout


def test_auth_profile_list_uses_metadata_only(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])
    runner.invoke(app, ["target", "add", "example.com", "--scope", "example.com"])
    runner.invoke(app, ["target", "use", "example.com"])
    result = runner.invoke(app, ["auth", "list"])
    assert result.exit_code == 0
    assert "No authentication profiles" in result.stdout
