from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import httpx
import typer
from keyring.errors import KeyringError

from bbai.auth.models import AuthProfile
from bbai.auth.redaction import redact_secrets
from bbai.auth.resolver import resolve_auth
from bbai.auth.store import KeyringSecretStore
from bbai.config import Settings
from bbai.context.builder import ContextInput, build_context
from bbai.db import init_db
from bbai.diagnostics import run_diagnostics
from bbai.llm.provider import OllamaProvider
from bbai.services.project_service import FindingData, ProjectService
from bbai.setup_wizard import run_setup_wizard
from bbai.tools.policy import ScopePolicy
from bbai.tools.registry import build_tools, tool_availability, tool_definitions

app = typer.Typer(help="Local research assistant for Bug Bounty investigations with Ollama.")

# Subcommands
_target_app = typer.Typer(help="Manage investigation targets.")
_evidence_app = typer.Typer(help="Manage stored investigation evidence.")
_observation_app = typer.Typer(help="Manage technical observations.")
_hypothesis_app = typer.Typer(help="Manage investigation hypotheses.")
_finding_app = typer.Typer(help="Manage findings.")
_session_app = typer.Typer(help="Manage investigation sessions.")
_tool_app = typer.Typer(help="Inspect available tool integrations.")
_auth_app = typer.Typer(help="Manage target authentication profiles.")
app.add_typer(_target_app, name="target")
app.add_typer(_evidence_app, name="evidence")
app.add_typer(_observation_app, name="observation")
app.add_typer(_hypothesis_app, name="hypothesis")
app.add_typer(_finding_app, name="finding")
app.add_typer(_session_app, name="session")
app.add_typer(_tool_app, name="tool")
app.add_typer(_auth_app, name="auth")


@app.callback()
def main() -> None:
    """Main CLI entry point."""


@app.command("init")
def init_project(
    project_root: str = typer.Option(
        ".", "--project-root", "-p", help="Project directory to initialize."
    ),
    setup_dependencies: bool = typer.Option(
        False, "--setup", help="Run the dependency setup wizard even if already completed."
    ),
    skip_dependency_setup: bool = typer.Option(
        False, "--skip-dependency-setup", help="Initialize without opening the setup wizard."
    ),
) -> None:
    if setup_dependencies and skip_dependency_setup:
        typer.echo("Use either --setup or --skip-dependency-setup, not both.", err=True)
        raise typer.Exit(code=2)
    root = Path(project_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    settings = Settings.load(root)
    settings.save()
    storage_dir = root / settings.data_dir
    storage_dir.mkdir(parents=True, exist_ok=True)
    init_db(str(settings.db_path))
    typer.echo(f"Project initialized at {root}")
    typer.echo(f"Database created at {settings.db_path}")
    should_run_setup = setup_dependencies or not settings.setup_wizard_completed
    if skip_dependency_setup:
        typer.echo("Dependency setup skipped. Run `bbai init --setup` to configure it later.")
    elif should_run_setup and not setup_dependencies and not sys.stdin.isatty():
        typer.echo(
            "Dependency setup needs an interactive terminal. "
            "Run `bbai init --setup` from a terminal to configure it."
        )
    elif should_run_setup:
        try:
            run_setup_wizard(settings)
        except (
            OSError,
            RuntimeError,
            ValueError,
            httpx.HTTPError,
            subprocess.CalledProcessError,
        ) as exc:
            typer.echo(f"Dependency setup failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        settings.setup_wizard_completed = True
        settings.save()


@_target_app.command("add")
def add_target(
    name: str = typer.Argument(..., help="Name of the target, e.g. example.com"),
    description: str = typer.Option("", "--description", "-d", help="Short summary of the target."),
    scope: str = typer.Option("", "--scope", "-s", help="Scope or asset list for the target."),
) -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    service.add_target(name=name, description=description or None, scope=scope or None)
    typer.echo(f"Target '{name}' added")


@_target_app.command("use")
def use_target(name: str = typer.Argument(..., help="Target to make active.")) -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    try:
        service.use_target(name)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if settings.active_target != name:
        settings.active_session_id = None
    settings.active_target = name
    settings.save()
    typer.echo(f"Active target: {name}")


@_auth_app.command("profile-add")
def add_auth_profile(
    name: str = typer.Argument(..., help="Profile name, e.g. normal-user."),
    auth_type: str = typer.Option(..., "--type", help="bearer, cookie, api_key or headers."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    allowed_types = {"bearer", "cookie", "api_key", "headers"}
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    if auth_type not in allowed_types:
        typer.echo(
            f"Unsupported auth type. Choose one of: {', '.join(sorted(allowed_types))}", err=True
        )
        raise typer.Exit(code=1)
    if auth_type == "bearer":
        payload = {"token": typer.prompt("Bearer token", hide_input=True)}
    elif auth_type == "cookie":
        payload = {"cookie": typer.prompt("Cookie header value", hide_input=True)}
    elif auth_type == "api_key":
        payload = {
            "header": typer.prompt("API key header", default="X-API-Key"),
            "value": typer.prompt("API key value", hide_input=True),
        }
    else:
        raw_headers = typer.prompt("Headers JSON (values are secrets)")
        try:
            parsed = json.loads(raw_headers)
        except json.JSONDecodeError as exc:
            typer.echo(f"Invalid headers JSON: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        if not isinstance(parsed, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
        ):
            typer.echo("Headers JSON must be an object with string keys and values.", err=True)
            raise typer.Exit(code=1)
        payload = parsed
    service = ProjectService(str(settings.db_path))
    secret_ref = f"{selected_target}/{name}"
    store = KeyringSecretStore()
    try:
        store.set(secret_ref, payload)
        profile_id = service.add_auth_profile(
            target_name=selected_target,
            name=name,
            auth_type=auth_type,
            secret_ref=secret_ref,
        )
    except Exception as exc:
        typer.echo(f"Unable to save authentication profile: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Authentication profile A-{profile_id:03d} '{name}' added to '{selected_target}'")


@_auth_app.command("list")
def list_auth_profiles(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    profiles = ProjectService(str(settings.db_path)).list_auth_profiles(target_name=selected_target)
    if not profiles:
        typer.echo("No authentication profiles recorded.")
        return
    for profile in profiles:
        typer.echo(f"- A-{profile['id']:03d} {profile['name']} [{profile['auth_type']}]")


@_auth_app.command("revoke")
def revoke_auth_profile(
    name: str = typer.Argument(..., help="Profile name."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        profile = service.disable_auth_profile(target_name=selected_target, name=name)
        KeyringSecretStore().delete(str(profile["secret_ref"]))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Authentication profile '{name}' revoked")


@app.command("status")
def status() -> None:
    settings = Settings.load(Path.cwd())
    if settings.active_target is None:
        typer.echo("No active target. Use: bbai target use <name>")
        return
    service = ProjectService(str(settings.db_path))
    target = service.get_target(settings.active_target)
    if target is None:
        typer.echo(f"Active target '{settings.active_target}' no longer exists.", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Active target: {target['name']}")
    typer.echo(f"Scope: {target['scope'] or 'Not specified'}")


@app.command("doctor")
def doctor() -> None:
    """Check workspace, database, Ollama, keyring and optional tool dependencies."""
    settings = Settings.load(Path.cwd())
    checks = run_diagnostics(settings)
    symbols = {"ok": "OK", "warning": "WARN", "error": "FAIL"}
    for check in checks:
        typer.echo(f"[{symbols[check['status']]}] {check['name']}: {check['detail']}")
    if any(check["status"] == "error" for check in checks):
        raise typer.Exit(code=1)


@app.command("search")
def search_artifacts(
    query: str | None = typer.Argument(None, help="Text to search for."),
    target_name: str = typer.Option("", "--target", "-t", help="Filter by target."),
    artifact_type: str = typer.Option(
        "",
        "--type",
        help="Filter: target, evidence, observation, hypothesis, finding, note, session_event.",
    ),
    session_id: int | None = typer.Option(None, "--session", help="Filter by numeric session ID."),
    status: str = typer.Option("", "--status", help="Filter by artifact status."),
    severity: str = typer.Option("", "--severity", help="Filter findings by severity."),
    limit: int = typer.Option(20, "--limit", min=1, max=100),
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild the full-text index."),
) -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    if rebuild:
        count = service.rebuild_search_index()
        typer.echo(f"Search index rebuilt ({count} artifacts).")
        if query is None:
            return
    if not query:
        typer.echo("Provide a query or use --rebuild.", err=True)
        raise typer.Exit(code=2)
    try:
        results = service.search_artifacts(
            query,
            target_name=target_name or None,
            artifact_type=artifact_type or None,
            session_id=session_id,
            status=status or None,
            severity=severity or None,
            limit=limit,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    if not results:
        typer.echo("No matching artifacts.")
        return
    for result in results:
        session = f" S-{result['session_id']:03d}" if result["session_id"] is not None else ""
        classification = " ".join(
            value
            for value in (result["status"], result["severity"])
            if isinstance(value, str) and value
        )
        typer.echo(
            f"- {result['type']}:{result['id']} [{result['target']}{session}] "
            f"{result['title']} {f'({classification})' if classification else ''}\n"
            f"  {result['snippet']}"
        )


@_session_app.command("create")
def create_session(
    title: str = typer.Argument(..., help="Short investigation objective."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    try:
        session_id = ProjectService(str(settings.db_path)).create_session(
            target_name=selected_target,
            title=title,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    settings.active_target = selected_target
    settings.active_session_id = session_id
    settings.save()
    typer.echo(f"Session S-{session_id:03d} created and active")


@_session_app.command("list")
def list_sessions(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    try:
        sessions = ProjectService(str(settings.db_path)).list_sessions(target_name=selected_target)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if not sessions:
        typer.echo("No sessions recorded yet.")
        return
    for session in sessions:
        active = " (active)" if session["id"] == settings.active_session_id else ""
        typer.echo(f"- S-{session['id']:03d} [{session['status']}] {session['title']}{active}")


@_session_app.command("show")
def show_session(
    session_id: int | None = typer.Argument(None, help="Numeric session ID."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_id = session_id or settings.active_session_id
    if selected_id is None:
        typer.echo("No active session. Create or resume one first.", err=True)
        raise typer.Exit(code=1)
    try:
        session = ProjectService(str(settings.db_path)).get_session(selected_id)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"S-{session['id']:03d} {session['title']}\n"
        f"Target: {session['target']} | Status: {session['status']}"
    )
    for note in session["notes"]:
        typer.echo(f"[note] {note['content']}")
    for event in session["events"]:
        typer.echo(f"[{event['type']}] {event['content']}")


@_session_app.command("resume")
def resume_session(session_id: int = typer.Argument(..., help="Numeric session ID.")) -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    try:
        service.set_session_status(session_id, status="active")
        session = service.get_session(session_id)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    settings.active_target = str(session["target"])
    settings.active_session_id = session_id
    settings.save()
    typer.echo(f"Session S-{session_id:03d} resumed and active")


@_session_app.command("note")
def add_session_note(
    content: str = typer.Argument(..., help="Research note."),
    session_id: int | None = typer.Option(None, "--session", help="Session ID override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_id = session_id or settings.active_session_id
    if selected_id is None:
        typer.echo("No active session. Create or resume one first.", err=True)
        raise typer.Exit(code=1)
    try:
        note_id = ProjectService(str(settings.db_path)).add_session_note(
            selected_id, content=content
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Note N-{note_id:03d} added to S-{selected_id:03d}")


@_session_app.command("pause")
def pause_session(
    session_id: int | None = typer.Argument(None, help="Numeric session ID."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_id = session_id or settings.active_session_id
    if selected_id is None:
        typer.echo("No active session to pause.", err=True)
        raise typer.Exit(code=1)
    try:
        ProjectService(str(settings.db_path)).set_session_status(selected_id, status="paused")
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if settings.active_session_id == selected_id:
        settings.active_session_id = None
        settings.save()
    typer.echo(f"Session S-{selected_id:03d} paused")


@_session_app.command("close")
def close_session(
    session_id: int | None = typer.Argument(None, help="Numeric session ID."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_id = session_id or settings.active_session_id
    if selected_id is None:
        typer.echo("No active session to close.", err=True)
        raise typer.Exit(code=1)
    try:
        ProjectService(str(settings.db_path)).set_session_status(selected_id, status="closed")
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if settings.active_session_id == selected_id:
        settings.active_session_id = None
        settings.save()
    typer.echo(f"Session S-{selected_id:03d} closed")


@_tool_app.command("list")
def list_tools() -> None:
    for name, status_value in tool_availability().items():
        typer.echo(f"- {name}: {status_value}")


@_tool_app.command("check")
def check_tools() -> None:
    availability = tool_availability()
    missing = [name for name, status_value in availability.items() if status_value == "missing"]
    for name, status_value in availability.items():
        typer.echo(f"- {name}: {status_value}")
    if missing:
        typer.echo(f"Missing optional tools: {', '.join(missing)}", err=True)
        raise typer.Exit(code=1)


@_tool_app.command("executions")
def list_tool_executions(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    executions = service.list_tool_executions(target_name=selected_target)
    if not executions:
        typer.echo("No tool executions recorded yet.")
        return
    for execution in executions:
        approval = "approved" if execution["approved"] else "not-approved"
        typer.echo(
            f"- T-{execution['id']:03d} {execution['tool_name']} "
            f"[{execution['status']}, {approval}, {execution['duration_ms']}ms]"
        )


@_evidence_app.command("add")
def add_evidence(
    path: str = typer.Argument(..., help="File containing evidence."),
    kind: str = typer.Option("text", "--kind", "-k", help="Evidence type, e.g. http-request."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    evidence_path = Path(path).expanduser().resolve()
    if not evidence_path.is_file():
        typer.echo(f"Evidence file not found: {evidence_path}", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        evidence_id = service.add_evidence(
            target_name=selected_target,
            source=str(evidence_path),
            kind=kind,
            content=evidence_path.read_text(encoding="utf-8"),
            session_id=settings.active_session_id,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Evidence E-{evidence_id:03d} added to '{selected_target}'")


@_evidence_app.command("list")
def list_evidence(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    evidence_items = service.list_evidence(target_name=selected_target)
    if not evidence_items:
        typer.echo("No evidence recorded yet.")
        return
    for item in evidence_items:
        typer.echo(f"- E-{item['id']:03d} [{item['kind']}] {item['source']}")


@_observation_app.command("add")
def add_observation(
    summary: str = typer.Argument(..., help="Technical observation."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    evidence_id: int | None = typer.Option(None, "--evidence", help="Evidence numeric ID."),
    tool_execution_id: int | None = typer.Option(
        None, "--execution", help="Tool execution numeric ID."
    ),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        observation_id = service.add_observation(
            target_name=selected_target,
            summary=summary,
            evidence_id=evidence_id,
            tool_execution_id=tool_execution_id,
            session_id=settings.active_session_id,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Observation O-{observation_id:03d} added to '{selected_target}'")


@_observation_app.command("list")
def list_observations(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    observations = ProjectService(str(settings.db_path)).list_observations(
        target_name=selected_target
    )
    if not observations:
        typer.echo("No observations recorded yet.")
        return
    for item in observations:
        typer.echo(f"- O-{item['id']:03d}: {item['summary']}")


@_hypothesis_app.command("add")
def add_hypothesis(
    statement: str = typer.Argument(..., help="Hypothesis to investigate."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    status: str = typer.Option("open", "--status"),
    confidence: str = typer.Option("unknown", "--confidence"),
    evidence_id: int | None = typer.Option(None, "--evidence", help="Evidence numeric ID."),
    observation_id: int | None = typer.Option(
        None, "--observation", help="Observation numeric ID."
    ),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        hypothesis_id = service.add_hypothesis(
            target_name=selected_target,
            statement=statement,
            status=status,
            confidence=confidence,
            evidence_id=evidence_id,
            observation_id=observation_id,
            session_id=settings.active_session_id,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Hypothesis H-{hypothesis_id:03d} added to '{selected_target}'")


@_hypothesis_app.command("list")
def list_hypotheses(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    hypotheses = ProjectService(str(settings.db_path)).list_hypotheses(target_name=selected_target)
    if not hypotheses:
        typer.echo("No hypotheses recorded yet.")
        return
    for item in hypotheses:
        typer.echo(
            f"- H-{item['id']:03d} [{item['status']}, {item['confidence']}]: {item['statement']}"
        )


@_hypothesis_app.command("update")
def update_hypothesis(
    hypothesis_id: int = typer.Argument(..., help="Numeric hypothesis ID."),
    status: str = typer.Option(..., "--status"),
    confidence: str | None = typer.Option(None, "--confidence"),
) -> None:
    settings = Settings.load(Path.cwd())
    try:
        ProjectService(str(settings.db_path)).update_hypothesis(
            hypothesis_id, status=status, confidence=confidence
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Hypothesis H-{hypothesis_id:03d} updated")


@_target_app.command("list")
def list_targets() -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    targets = service.list_targets()
    if not targets:
        typer.echo("No targets available.")
        return
    for target in targets:
        typer.echo(f"- {target['name']}: {target['description'] or 'No description'}")


@app.command("ask")
def ask_question(
    question: str = typer.Argument(..., help="The question to send to the local model."),
    target_name: str = typer.Option(
        "", "--target", "-t", help="Optional target name to include in the context."
    ),
    model: str | None = typer.Option(None, "--model", "-m", help="Optional model name override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    service = ProjectService(str(settings.db_path))
    if selected_target:
        try:
            context_data = service.get_context_data(target_name=selected_target)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    else:
        context_data = {
            "target": "General investigation context",
            "scope": "",
            "assets": "",
            "endpoints": "",
            "evidence": "",
            "previous_findings": "",
            "observations": "",
            "hypotheses": "",
        }
    provider = OllamaProvider(
        base_url=settings.ollama.base_url,
        default_model=settings.ollama.default_model,
        timeout_seconds=settings.ollama.timeout_seconds,
    )

    payload = ContextInput(
        target=context_data["target"],
        scope=context_data["scope"],
        assets=context_data["assets"],
        endpoints=context_data["endpoints"],
        recon="No reconnaissance notes yet.",
        http_observations="No HTTP observations recorded.",
        previous_findings=context_data["previous_findings"],
        observations=context_data["observations"],
        hypotheses=context_data["hypotheses"],
        evidence=context_data["evidence"],
        question=question,
    )
    prompt = redact_secrets(build_context(payload))

    try:
        response = asyncio.run(
            provider.generate(
                prompt,
                model=model,
                system="You are a careful bug bounty research assistant. Keep the investigator in the loop and never act autonomously.",
            )
        )
    except Exception as exc:  # pragma: no cover - defensive CLI error handling
        typer.echo(f"Unable to contact Ollama at {settings.ollama.base_url}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(response)


@app.command("investigate")
def investigate(
    question: str = typer.Argument(..., help="Investigation question for the local model."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    auth_name: str = typer.Option("", "--auth", help="Authentication profile name."),
    session_id: int | None = typer.Option(None, "--session", help="Session ID to resume/use."),
    model: str | None = typer.Option(None, "--model", "-m", help="Optional model name override."),
    max_steps: int = typer.Option(4, "--max-steps", min=1, max=8, help="Maximum model/tool turns."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show proposed tools without executing them."
    ),
) -> None:
    """Ask Ollama to investigate using approved, human-confirmed tools."""
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        context_data = service.get_context_data(target_name=selected_target)
        target = service.get_target(selected_target)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    scope = (target or {}).get("scope")
    if not scope:
        typer.echo("The target has no scope. Add one before enabling tools.", err=True)
        raise typer.Exit(code=1)

    selected_session_id = session_id or settings.active_session_id
    if selected_session_id is None:
        selected_session_id = service.create_session(
            target_name=selected_target,
            title=question[:255],
        )
        settings.active_target = selected_target
        settings.active_session_id = selected_session_id
        settings.save()
    try:
        session_data = service.get_session(selected_session_id)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if session_data["target"] != selected_target:
        typer.echo("The selected session belongs to a different target.", err=True)
        raise typer.Exit(code=1)
    if session_data["status"] != "active":
        typer.echo(
            "The selected session is not active. Resume it with 'bbai session resume'.", err=True
        )
        raise typer.Exit(code=1)
    settings.active_target = selected_target
    settings.active_session_id = selected_session_id
    settings.save()

    auth_context = None
    auth_label = "unauthenticated"
    if auth_name:
        profile_data = service.get_auth_profile(target_name=selected_target, name=auth_name)
        if profile_data is None:
            typer.echo(f"Authentication profile '{auth_name}' does not exist", err=True)
            raise typer.Exit(code=1)
        expires_at = profile_data["expires_at"]
        if expires_at is not None and not isinstance(expires_at, datetime):
            typer.echo("Authentication profile has an invalid expiration value", err=True)
            raise typer.Exit(code=1)
        profile = AuthProfile(
            name=str(profile_data["name"]),
            auth_type=str(profile_data["auth_type"]),
            secret_ref=str(profile_data["secret_ref"]),
            expires_at=expires_at,
        )
        try:
            auth_context = resolve_auth(profile, KeyringSecretStore())
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
        auth_label = auth_context.label

    provider = OllamaProvider(
        base_url=settings.ollama.base_url,
        default_model=settings.ollama.default_model,
        timeout_seconds=settings.ollama.timeout_seconds,
    )
    tool_timeout = min(settings.ollama.timeout_seconds, 60)
    tools = build_tools(scope=scope, timeout_seconds=tool_timeout, auth=auth_context)
    policy = ScopePolicy(allowed_tools=frozenset(tools), approval_required=True)
    definitions = tool_definitions(tools)
    context = build_context(
        ContextInput(
            target=context_data["target"],
            scope=context_data["scope"],
            assets=context_data["assets"],
            endpoints=context_data["endpoints"],
            recon="No reconnaissance notes yet.",
            http_observations="No HTTP observations recorded.",
            previous_findings=context_data["previous_findings"],
            observations=context_data["observations"],
            hypotheses=context_data["hypotheses"],
            evidence=context_data["evidence"],
            question=question,
        )
    )
    recent_events = session_data["events"][-20:]
    recent_notes = session_data["notes"][-20:]
    history_lines = [
        f"- [{event['type']}] {event['content']}"
        for event in recent_events
        if isinstance(event, dict)
    ]
    history_lines.extend(
        f"- [note] {note['content']}" for note in recent_notes if isinstance(note, dict)
    )
    if history_lines:
        context += "\n\nRecent session history:\n" + "\n".join(history_lines)
    context = redact_secrets(
        context,
        auth_context.secret_values if auth_context else (),
    )
    service.add_session_event(
        selected_session_id,
        event_type="question",
        content=question,
        secret_values=auth_context.secret_values if auth_context else (),
    )
    if auth_context:
        service.add_session_event(
            selected_session_id,
            event_type="auth_profile",
            content=auth_context.label,
            details={"profile": auth_context.profile.name},
        )
    messages: list[dict[str, object]] = [
        {
            "role": "user",
            "content": (
                f"{context}\n\n"
                f"Authentication profile: {auth_label}. "
                "You may propose read-only GET requests, passive subdomain enumeration, "
                "or bounded content discovery. "
                "Do not claim a request was made unless tool output confirms it."
            ),
        }
    ]
    system = (
        "You are a cautious bug bounty research assistant. Stay within the approved scope. "
        "Use tools only when useful, explain why, and never perform state-changing actions."
    )

    try:
        for _ in range(max_steps):
            turn = asyncio.run(
                provider.chat_with_tools(
                    messages,
                    tools=definitions,
                    model=model,
                    system=system,
                )
            )
            messages.append(turn.message)
            if not turn.tool_calls:
                service.add_session_event(
                    selected_session_id,
                    event_type="assistant",
                    content=turn.text,
                    secret_values=auth_context.secret_values if auth_context else (),
                )
                typer.echo(turn.text)
                return
            for call in turn.tool_calls:
                policy.validate_tool(call.name)
                tool = tools[call.name]
                secret_values = auth_context.secret_values if auth_context else ()
                safe_arguments = _redact_mapping(call.arguments, secret_values)
                service.add_session_event(
                    selected_session_id,
                    event_type="tool_call",
                    content=call.name,
                    details={"arguments": safe_arguments},
                    secret_values=secret_values,
                )
                typer.echo(
                    f"\nEl modelo solicita usar {call.name}: {call.arguments} (auth: {auth_label})"
                )
                started = time.monotonic()
                if dry_run:
                    result = "Dry run: tool was not executed."
                    execution_status = "dry_run"
                    approved = False
                elif not policy.requires_approval(call.name) or not typer.confirm(
                    "¿Autorizar esta herramienta?", default=False
                ):
                    result = "Human approval denied; do not retry this tool call."
                    execution_status = "denied"
                    approved = False
                else:
                    try:
                        result = tool.execute(**call.arguments)
                        execution_status = "succeeded"
                        approved = True
                        service.add_evidence(
                            target_name=selected_target,
                            source=f"tool:{tool.name}:{safe_arguments}",
                            kind=f"tool-{tool.name}",
                            content=result,
                            session_id=selected_session_id,
                        )
                    except (RuntimeError, TypeError, ValueError, httpx.HTTPError) as exc:
                        result = redact_secrets(
                            f"Tool execution failed: {exc}",
                            secret_values,
                        )
                        execution_status = "failed"
                        approved = True
                result = redact_secrets(result, secret_values)
                service.add_tool_execution(
                    target_name=selected_target,
                    tool_name=call.name,
                    arguments=safe_arguments,
                    status=execution_status,
                    approved=approved,
                    output=result if execution_status == "succeeded" else None,
                    error=result if execution_status in {"failed", "denied"} else None,
                    duration_ms=round((time.monotonic() - started) * 1000),
                    session_id=selected_session_id,
                )
                service.add_session_event(
                    selected_session_id,
                    event_type="tool_result",
                    content=result,
                    details={
                        "tool": call.name,
                        "status": execution_status,
                        "approved": approved,
                    },
                    secret_values=secret_values,
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": call.name,
                        "content": result,
                    }
                )
        typer.echo(
            "The investigation reached the maximum tool steps without a final answer.", err=True
        )
        raise typer.Exit(code=1)
    except (httpx.HTTPError, RuntimeError, TypeError, ValueError) as exc:
        typer.echo(f"Investigation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("analyze")
def analyze_evidence(
    path: str = typer.Argument(..., help="File containing evidence or a request to analyze."),
    target_name: str = typer.Option(
        "", "--target", "-t", help="Optional target name to include in the context."
    ),
    model: str | None = typer.Option(None, "--model", "-m", help="Optional model name override."),
) -> None:
    evidence_path = Path(path).expanduser().resolve()
    if not evidence_path.exists():
        typer.echo(f"Evidence file not found: {evidence_path}", err=True)
        raise typer.Exit(code=1)

    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    service = ProjectService(str(settings.db_path))
    if selected_target:
        try:
            context_data = service.get_context_data(target_name=selected_target)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from exc
    else:
        context_data = {
            "target": "General investigation context",
            "scope": "",
            "assets": "",
            "endpoints": "",
            "previous_findings": "",
            "observations": "",
            "hypotheses": "",
        }
    provider = OllamaProvider(
        base_url=settings.ollama.base_url,
        default_model=settings.ollama.default_model,
        timeout_seconds=settings.ollama.timeout_seconds,
    )

    evidence = evidence_path.read_text(encoding="utf-8")
    payload = ContextInput(
        target=context_data["target"],
        scope=context_data["scope"],
        assets=context_data["assets"],
        endpoints=context_data["endpoints"],
        recon="Evidence analysis request.",
        http_observations="No HTTP observations recorded.",
        previous_findings=context_data["previous_findings"],
        observations=context_data["observations"],
        hypotheses=context_data["hypotheses"],
        evidence=evidence,
        question="Analyze this evidence and summarize what is relevant to the investigation.",
    )
    prompt = redact_secrets(build_context(payload))

    try:
        response = asyncio.run(
            provider.generate(
                prompt,
                model=model,
                system="You are a cautious assistant for technical evidence review. Stay within the human-approved investigation scope.",
            )
        )
    except Exception as exc:  # pragma: no cover - defensive CLI error handling
        typer.echo(f"Unable to contact Ollama at {settings.ollama.base_url}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(response)


@_finding_app.command("list")
def list_findings(
    target_name: str = typer.Option("", "--target", "-t", help="Optional target filter."),
) -> None:
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    findings = service.list_findings(target_name=target_name or None)
    if not findings:
        typer.echo("No findings recorded yet.")
        return
    for finding in findings:
        typer.echo(
            f"- F-{finding['id']:03d} {finding['title']} "
            f"[{finding['severity']}, {finding['status']}]"
        )


@_finding_app.command("create")
def create_finding(
    title: str = typer.Argument(..., help="Finding title."),
    summary: str = typer.Argument(..., help="Technical summary of the finding."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    severity: str = typer.Option("info", "--severity"),
    confidence: str = typer.Option("unknown", "--confidence"),
    impact: str = typer.Option("", "--impact"),
    reproduction: str = typer.Option("", "--reproduction"),
    remediation: str = typer.Option("", "--remediation"),
    evidence_ids: Annotated[list[int] | None, typer.Option("--evidence")] = None,
    observation_ids: Annotated[list[int] | None, typer.Option("--observation")] = None,
    hypothesis_ids: Annotated[list[int] | None, typer.Option("--hypothesis")] = None,
    execution_ids: Annotated[list[int] | None, typer.Option("--execution")] = None,
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("No target selected. Use 'bbai target use <name>' or pass --target.", err=True)
        raise typer.Exit(code=1)
    try:
        finding_id = ProjectService(str(settings.db_path)).add_finding(
            target_name=selected_target,
            title=title,
            summary=summary,
            severity=severity,
            confidence=confidence,
            impact=impact,
            reproduction=reproduction,
            remediation=remediation,
            evidence_ids=evidence_ids,
            observation_ids=observation_ids,
            hypothesis_ids=hypothesis_ids,
            execution_ids=execution_ids,
            session_id=settings.active_session_id,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Finding F-{finding_id:03d} created as draft")


@_finding_app.command("show")
def show_finding(finding_id: int = typer.Argument(..., help="Numeric finding ID.")) -> None:
    try:
        finding = ProjectService(str(Settings.load(Path.cwd()).db_path)).get_finding(finding_id)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"F-{finding['id']:03d} {finding['title']}\n"
        f"Target: {finding['target']}\n"
        f"Status: {finding['status']} | Severity: {finding['severity']} "
        f"| Confidence: {finding['confidence']}\n"
        f"Summary: {finding['summary']}\n"
        f"Impact: {finding['impact']}\n"
        f"Reproduction: {finding['reproduction']}\n"
        f"Remediation: {finding['remediation']}\n"
        f"Evidence IDs: {', '.join(str(item['id']) for item in finding['evidence']) or 'none'}\n"
        f"Observations: {', '.join(str(item['id']) for item in finding['observations']) or 'none'}\n"
        f"Hypotheses: {', '.join(str(item['id']) for item in finding['hypotheses']) or 'none'}\n"
        f"Reviews: {len(finding['reviews'])}"
    )


@_finding_app.command("update")
def update_finding(
    finding_id: int = typer.Argument(..., help="Numeric finding ID."),
    status: str | None = typer.Option(None, "--status"),
    severity: str | None = typer.Option(None, "--severity"),
    confidence: str | None = typer.Option(None, "--confidence"),
    impact: str | None = typer.Option(None, "--impact"),
    reproduction: str | None = typer.Option(None, "--reproduction"),
    remediation: str | None = typer.Option(None, "--remediation"),
) -> None:
    if all(
        value is None for value in (status, severity, confidence, impact, reproduction, remediation)
    ):
        typer.echo("Provide at least one field to update.", err=True)
        raise typer.Exit(code=1)
    try:
        ProjectService(str(Settings.load(Path.cwd()).db_path)).update_finding(
            finding_id,
            status=status,
            severity=severity,
            confidence=confidence,
            impact=impact,
            reproduction=reproduction,
            remediation=remediation,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Finding F-{finding_id:03d} updated")


@_finding_app.command("review")
def review_finding(
    finding_id: int = typer.Argument(..., help="Numeric finding ID."),
    decision: str = typer.Option(..., "--decision", help="accepted or rejected."),
    note: str = typer.Option("", "--note", help="Reviewer rationale."),
) -> None:
    try:
        ProjectService(str(Settings.load(Path.cwd()).db_path)).review_finding(
            finding_id, decision=decision, note=note
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Finding F-{finding_id:03d} {decision}")


@app.command("report")
def generate_report(
    finding_id: int | None = typer.Argument(None, help="Optional numeric finding ID."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    output_format: str = typer.Option("markdown", "--format", help="markdown or json."),
    output_path: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write report to a file.")
    ] = None,
    include_drafts: bool = typer.Option(
        False, "--include-drafts", help="Explicitly include findings not yet accepted."
    ),
) -> None:
    if output_format not in {"markdown", "json"}:
        typer.echo("Format must be 'markdown' or 'json'.", err=True)
        raise typer.Exit(code=1)
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    service = ProjectService(str(settings.db_path))
    try:
        findings = service.report_findings(
            target_name=selected_target,
            finding_id=finding_id,
            include_drafts=include_drafts,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if not findings:
        typer.echo("No accepted findings to report.", err=True)
        raise typer.Exit(code=1)
    target_names = {str(finding["target"]) for finding in findings}
    secrets: list[str] = []
    store = KeyringSecretStore()
    try:
        for name in target_names:
            for profile in service.list_auth_profiles(target_name=name):
                payload = store.get(str(profile["secret_ref"]))
                secrets.extend(payload.values())
    except (KeyringError, ValueError) as exc:
        typer.echo(f"Unable to verify report redaction: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _redact_report_data(findings, secrets)
    if output_format == "json":
        rendered = json.dumps(findings, ensure_ascii=False, indent=2)
    else:
        rendered = _render_markdown_report(findings)
    rendered = redact_secrets(rendered, secrets)
    if output_path:
        output_path = output_path.expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
        typer.echo(f"Report written to {output_path}")
    else:
        typer.echo(rendered)


def _redact_report_data(value: object, secrets: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                _redact_report_data(item, secrets)
            elif isinstance(item, str):
                value[key] = redact_secrets(item, secrets)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (dict, list)):
                _redact_report_data(item, secrets)
            elif isinstance(item, str):
                value[index] = redact_secrets(item, secrets)


def _redact_mapping(
    values: dict[str, object],
    secrets: tuple[str, ...],
) -> dict[str, object]:
    return {key: _redact_nested(value, secrets) for key, value in values.items()}


def _redact_nested(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, str):
        return redact_secrets(value, secrets)
    if isinstance(value, dict):
        return {str(key): _redact_nested(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_nested(item, secrets) for item in value]
    return value


def _render_markdown_report(findings: list[FindingData]) -> str:
    sections = ["# Bug Bounty Findings Report"]
    for finding in findings:
        sections.extend(
            [
                f"## {finding['title']}",
                "",
                f"- Target: {finding['target']}",
                f"- Severity: {finding['severity']}",
                f"- Confidence: {finding['confidence']}",
                f"- Status: {finding['status']}",
                f"- Session: {finding['session_title'] or 'unspecified'}",
                f"- Authentication profiles: {', '.join(finding['auth_profiles']) or 'none'}",
                "",
                str(finding["summary"]),
                "",
                "### Impact",
                "",
                str(finding["impact"]),
                "",
                "### Reproduction",
                "",
                str(finding["reproduction"]),
                "",
                "### Remediation",
                "",
                str(finding["remediation"]),
                "",
                "### Evidence",
                "",
            ]
        )
        evidence_items = finding["evidence"]
        if not evidence_items:
            sections.append("No linked evidence.")
        for item in evidence_items:
            sections.extend(
                [
                    f"#### E-{item['id']:03d}: {item['kind']} ({item['source']})",
                    "",
                    "```text",
                    str(item["content"]).replace("```", "` ` `"),
                    "```",
                    "",
                ]
            )
        reviews = finding["reviews"]
        if reviews:
            sections.extend(["### Review notes", ""])
            sections.extend(
                f"- {item['decision']} by {item['reviewer']}: {item['note']}" for item in reviews
            )
            sections.append("")
    return "\n".join(sections).rstrip()


if __name__ == "__main__":
    app()
