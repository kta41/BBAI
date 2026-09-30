from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

import httpx
import typer

from bbai.config import Settings
from bbai.diagnostics import OPTIONAL_TOOLS

GO_MODULES = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
}
OLLAMA_INSTALL_URL = "https://ollama.com/install.sh"


def run_setup_wizard(
    settings: Settings,
    *,
    prompt: Callable[..., str] = typer.prompt,
    confirm: Callable[..., bool] = typer.confirm,
) -> None:
    missing_tools = [tool for tool in OPTIONAL_TOOLS if shutil.which(tool) is None]
    if missing_tools:
        typer.echo("Optional tools not found: " + ", ".join(missing_tools))
        selection = (
            prompt(
                "Choose tool setup: [a]ll missing, [s]elect tools, [n]ot now",
                default="n",
            )
            .strip()
            .lower()
        )
        if selection == "a":
            selected_tools = missing_tools
        elif selection == "s":
            selected_tools = [
                tool for tool in missing_tools if confirm(f"Install {tool}?", default=False)
            ]
        elif selection == "n":
            selected_tools = []
        else:
            raise ValueError("Choose 'a', 's', or 'n' for tool setup.")
        if selected_tools:
            _install_go_tools(selected_tools)
    else:
        typer.echo("All optional security tools are already installed.")

    if shutil.which("ollama") is None:
        if confirm("Install Ollama using its official Linux installer?", default=False):
            _install_ollama()
    else:
        typer.echo("Ollama executable found.")

    if shutil.which("ollama") is None:
        typer.echo("Ollama is not installed; rerun `bbai init --setup` to configure it.")
        return
    ollama_status = _ollama_model_status(settings)
    if ollama_status == "unreachable":
        typer.echo(
            "Ollama is not responding. Start it with `ollama serve` "
            "and rerun `bbai init` to download/check the configured model."
        )
    elif ollama_status == "missing":
        if confirm(
            f"Download configured model '{settings.ollama.default_model}'? "
            "This may require several gigabytes.",
            default=False,
        ):
            subprocess.run(
                ["ollama", "pull", settings.ollama.default_model],
                check=True,
            )
    else:
        typer.echo(f"Configured Ollama model '{settings.ollama.default_model}' is ready.")


def _install_go_tools(tool_names: list[str]) -> None:
    go = shutil.which("go")
    if go is None:
        typer.echo(
            "Cannot install the selected tools because Go is missing. "
            "Install Go from https://go.dev/dl/, then rerun `bbai init`.",
            err=True,
        )
        raise RuntimeError("Go is required to install the selected tools.")
    install_dir = Path.home() / ".local" / "bin"
    install_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["GOBIN"] = str(install_dir)
    environment["PATH"] = f"{install_dir}{os.pathsep}{environment.get('PATH', '')}"
    for tool_name in tool_names:
        typer.echo(f"Installing {tool_name}...")
        subprocess.run(
            [go, "install", GO_MODULES[tool_name]],
            check=True,
            env=environment,
        )
    os.environ["PATH"] = environment["PATH"]
    typer.echo(f"Selected tools installed in {install_dir}.")


def _install_ollama() -> None:
    typer.echo(f"Downloading the installer from {OLLAMA_INSTALL_URL}")
    response = httpx.get(OLLAMA_INSTALL_URL, timeout=30, follow_redirects=True)
    response.raise_for_status()
    with tempfile.TemporaryDirectory(prefix="bbai-ollama-install-") as temp_dir:
        script = Path(temp_dir) / "install-ollama.sh"
        script.write_bytes(response.content)
        typer.echo("Running the selected Ollama installer; it may request administrator access.")
        subprocess.run(["sh", str(script)], check=True)


def _ollama_model_status(settings: Settings) -> str:
    if shutil.which("ollama") is None:
        return "unreachable"
    try:
        response = httpx.get(
            f"{settings.ollama.base_url.rstrip('/')}/api/tags",
            timeout=2,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return "unreachable"
    models = payload.get("models", []) if isinstance(payload, dict) else []
    if not isinstance(models, list):
        return "missing"
    desired = settings.ollama.default_model
    found = any(
        isinstance(model, dict)
        and isinstance(model.get("name"), str)
        and (model["name"] == desired or model["name"].split(":", 1)[0] == desired.split(":", 1)[0])
        for model in models
    )
    return "ready" if found else "missing"
