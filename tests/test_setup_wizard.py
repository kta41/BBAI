from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from bbai.config import Settings
from bbai.setup_wizard import run_setup_wizard


def test_setup_wizard_installs_only_selected_tool(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        "bbai.setup_wizard.shutil.which",
        lambda executable: "/usr/bin/go" if executable == "go" else None,
    )
    monkeypatch.setattr(
        "bbai.setup_wizard.subprocess.run",
        lambda command, **kwargs: commands.append(command),
    )
    confirmations: list[str] = []

    def confirm(message: str, *, default: bool) -> bool:
        confirmations.append(message)
        return message == "Install katana?"

    run_setup_wizard(
        Settings(project_root=tmp_path),
        prompt=lambda *args, **kwargs: "s",
        confirm=confirm,
    )

    assert commands == [
        ["/usr/bin/go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"]
    ]
    assert any("Install nuclei?" in message for message in confirmations)
    assert any("Install Ollama" in message for message in confirmations)


def test_setup_wizard_reports_missing_go_instead_of_claiming_install_succeeded(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr("bbai.setup_wizard.shutil.which", lambda _: None)
    try:
        run_setup_wizard(
            Settings(project_root=tmp_path),
            prompt=lambda *args, **kwargs: "a",
            confirm=lambda *args, **kwargs: False,
        )
    except RuntimeError as exc:
        assert "Go is required" in str(exc)
    else:
        raise AssertionError("selected Go tools must not report success without Go")


def test_setup_wizard_downloads_configured_model_only_after_confirmation(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "bbai.setup_wizard.shutil.which",
        lambda executable: "/usr/bin/ollama" if executable == "ollama" else "/usr/bin/tool",
    )
    monkeypatch.setattr(
        "bbai.setup_wizard._ollama_model_status",
        lambda settings: "missing",
    )
    monkeypatch.setattr(
        "bbai.setup_wizard.subprocess.run",
        lambda command, **kwargs: commands.append(command),
    )

    run_setup_wizard(
        Settings(project_root=tmp_path),
        prompt=lambda *args, **kwargs: "n",
        confirm=lambda message, **kwargs: message.startswith("Download configured model"),
    )

    assert commands == [["ollama", "pull", "llama3.1"]]
