from __future__ import annotations

import asyncio
import hashlib
import json
import math
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from string import Template
from typing import Annotated

import httpx
import typer
from keyring.errors import KeyringError
from sqlalchemy.exc import SQLAlchemyError

from bbai.audit import ExecutionStatus, append_tool_audit_event
from bbai.auth.models import AuthProfile
from bbai.auth.redaction import redact_secrets
from bbai.auth.resolver import resolve_auth
from bbai.auth.store import KeyringSecretStore
from bbai.backup import BackupError, create_database_backup, restore_database_backup
from bbai.config import Settings
from bbai.context.builder import ContextInput, build_context
from bbai.db import init_db
from bbai.diagnostics import run_diagnostics
from bbai.filesystem import atomic_write_private
from bbai.importers import MAX_IMPORT_BYTES, parse_nuclei_jsonl, parse_sarif
from bbai.llm.provider import OllamaProvider
from bbai.semantic import rank_semantically
from bbai.services.project_service import FindingData, ImportedFindingInput, ProjectService
from bbai.setup_wizard import run_setup_wizard
from bbai.tools.base import HttpInspectTool
from bbai.tools.policy import ScopePolicy
from bbai.tools.registry import (
    build_tools,
    tool_availability,
    tool_definitions,
    tool_security_metadata,
)
from bbai.workspace_archive import export_workspace, import_workspace

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
_workspace_app = typer.Typer(help="Export and import portable workspaces.")
app.add_typer(_target_app, name="target")
app.add_typer(_evidence_app, name="evidence")
app.add_typer(_observation_app, name="observation")
app.add_typer(_hypothesis_app, name="hypothesis")
app.add_typer(_finding_app, name="finding")
app.add_typer(_session_app, name="session")
app.add_typer(_tool_app, name="tool")
app.add_typer(_auth_app, name="auth")
app.add_typer(_workspace_app, name="workspace")


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
    auth_type: str = typer.Option("headers", "--type", help="bearer, cookie, api_key or headers."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    role: str = typer.Option("custom", "--role", help="anonymous, user, admin, or custom."),
    expires_at: str = typer.Option("", "--expires-at", help="ISO-8601 expiration with timezone."),
    expires_in_hours: float | None = typer.Option(
        None, "--expires-in-hours", min=0.01, help="Expire after this many hours."
    ),
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
    if role not in {"anonymous", "user", "admin", "custom"}:
        typer.echo("Role must be anonymous, user, admin, or custom.", err=True)
        raise typer.Exit(code=2)
    if expires_at and expires_in_hours is not None:
        typer.echo("Choose either --expires-at or --expires-in-hours.", err=True)
        raise typer.Exit(code=2)
    try:
        expiration = datetime.fromisoformat(expires_at) if expires_at else None
    except ValueError as exc:
        typer.echo("--expires-at must be an ISO-8601 timestamp.", err=True)
        raise typer.Exit(code=2) from exc
    if expiration is not None and expiration.tzinfo is None:
        typer.echo("--expires-at must include a timezone.", err=True)
        raise typer.Exit(code=2)
    if expires_in_hours is not None:
        if not math.isfinite(expires_in_hours):
            typer.echo("--expires-in-hours must be a finite number.", err=True)
            raise typer.Exit(code=2)
        expiration = datetime.now(UTC) + timedelta(hours=expires_in_hours)
    service = ProjectService(str(settings.db_path))
    if service.get_target(selected_target) is None:
        typer.echo(f"Target '{selected_target}' does not exist.", err=True)
        raise typer.Exit(code=1)
    if service.auth_profile_exists(target_name=selected_target, name=name):
        typer.echo(
            f"Authentication profile '{name}' already exists for '{selected_target}'.", err=True
        )
        raise typer.Exit(code=1)
    if role == "anonymous":
        payload: dict[str, str] = {}
    elif auth_type == "bearer":
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
    secret_ref = f"{selected_target}/{name}"
    store = KeyringSecretStore()
    if role != "anonymous":
        try:
            store.set(secret_ref, payload)
        except (KeyringError, OSError, ValueError) as exc:
            typer.echo(
                f"Unable to store authentication secret in the system keyring: {exc}", err=True
            )
            raise typer.Exit(code=1) from exc
    try:
        profile_id = service.add_auth_profile(
            target_name=selected_target,
            name=name,
            auth_type=auth_type,
            secret_ref=secret_ref,
            role=role,
            expires_at=expiration,
        )
    except (SQLAlchemyError, ValueError) as exc:
        if role != "anonymous":
            try:
                store.delete(secret_ref)
            except (KeyringError, OSError) as cleanup_error:
                typer.echo(
                    "Unable to save authentication profile and unable to remove the "
                    f"orphaned keyring entry: {cleanup_error}",
                    err=True,
                )
                raise typer.Exit(code=1) from cleanup_error
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
        expiration = profile["expires_at"]
        if expiration is not None and not isinstance(expiration, datetime):
            raise RuntimeError("Authentication profile has an invalid expiration value.")
        expiry_label = f", expires {expiration.isoformat()}" if expiration else ""
        typer.echo(
            f"- A-{profile['id']:03d} {profile['name']} "
            f"[{profile['role']}, {profile['auth_type']}{expiry_label}]"
        )


@_auth_app.command("cookie-import")
def import_cookie_profile(
    name: str = typer.Argument(..., help="Name for the imported cookie profile."),
    cookie_file: Path = typer.Argument(  # noqa: B008
        ..., help="File containing a Cookie header value."
    ),
    target_name: str = typer.Option("", "--target", "-t"),
    role: str = typer.Option("user", "--role", help="user, admin, or custom."),
    expires_at: str = typer.Option("", "--expires-at", help="ISO-8601 expiration with timezone."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("Select a target or pass --target.", err=True)
        raise typer.Exit(code=1)
    if role not in {"user", "admin", "custom"}:
        typer.echo("Cookie profile role must be user, admin, or custom.", err=True)
        raise typer.Exit(code=2)
    service = ProjectService(str(settings.db_path))
    if service.get_target(selected_target) is None:
        typer.echo(f"Target '{selected_target}' does not exist.", err=True)
        raise typer.Exit(code=1)
    if service.auth_profile_exists(target_name=selected_target, name=name):
        typer.echo(
            f"Authentication profile '{name}' already exists for '{selected_target}'.", err=True
        )
        raise typer.Exit(code=1)
    try:
        if cookie_file.stat().st_size > 64 * 1024:
            raise ValueError("Cookie files are limited to 64 KiB")
        expiration = datetime.fromisoformat(expires_at) if expires_at else None
        if expiration is not None and expiration.tzinfo is None:
            raise ValueError("Expiration must include a timezone")
        cookie = cookie_file.expanduser().read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError, ValueError) as exc:
        typer.echo(f"Unable to read cookie file or expiration: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if cookie.lower().startswith("cookie:"):
        cookie = cookie.split(":", 1)[1].strip()
    if not cookie or "\n" in cookie or "\r" in cookie:
        typer.echo("Cookie file must contain one non-empty Cookie header value.", err=True)
        raise typer.Exit(code=2)
    if not typer.confirm(
        "Import this cookie into the system keyring? The file will not be deleted.",
        default=False,
    ):
        typer.echo("Cookie import cancelled.")
        return
    secret_ref = f"{selected_target}/{name}"
    store = KeyringSecretStore()
    try:
        store.set(secret_ref, {"cookie": cookie})
        profile_id = service.add_auth_profile(
            target_name=selected_target,
            name=name,
            auth_type="cookie",
            secret_ref=secret_ref,
            role=role,
            expires_at=expiration,
        )
    except (KeyringError, OSError, SQLAlchemyError, ValueError) as exc:
        try:
            store.delete(secret_ref)
        except (KeyringError, OSError) as cleanup_error:
            typer.echo(f"Cookie import failed; keyring cleanup failed: {cleanup_error}", err=True)
            raise typer.Exit(code=1) from cleanup_error
        typer.echo(f"Cookie import failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Authentication profile A-{profile_id:03d} imported; cookie value was not displayed."
    )


@_auth_app.command("compare")
def compare_auth_profiles(
    url: str = typer.Option(..., "--url", help="In-scope URL for read-only GET requests."),
    left_name: str = typer.Option(..., "--left", help="First auth profile name."),
    right_name: str = typer.Option(..., "--right", help="Second auth profile name."),
    target_name: str = typer.Option("", "--target", "-t"),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("Select a target or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    target = service.get_target(selected_target)
    if target is None or not target["scope"]:
        typer.echo("Target must exist and have an explicit scope.", err=True)
        raise typer.Exit(code=1)
    profiles: list[AuthProfile] = []
    for name in (left_name, right_name):
        data = service.get_auth_profile(target_name=selected_target, name=name)
        if data is None:
            typer.echo(f"Authentication profile '{name}' does not exist.", err=True)
            raise typer.Exit(code=1)
        expiration = data["expires_at"]
        profiles.append(
            AuthProfile(
                name=str(data["name"]),
                auth_type=str(data["auth_type"]),
                secret_ref=str(data["secret_ref"]),
                expires_at=expiration if isinstance(expiration, datetime) else None,
                role=str(data["role"]),
            )
        )
    contexts = []
    try:
        store = KeyringSecretStore()
        contexts = [resolve_auth(profile, store) for profile in profiles]
    except (KeyringError, ValueError) as exc:
        typer.echo(f"Unable to resolve authentication profile: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    fingerprints: list[tuple[int, str, str]] = []
    for profile, context in zip(profiles, contexts, strict=True):
        if not typer.confirm(
            f"Authorize one read-only GET to the scoped URL using role '{profile.role}'?",
            default=False,
        ):
            typer.echo("Comparison cancelled; both requests must be approved.", err=True)
            raise typer.Exit(code=1)
        try:
            response = HttpInspectTool(
                scope=str(target["scope"]),
                timeout_seconds=min(settings.ollama.timeout_seconds, 15),
                auth=context,
            ).execute(url=url)
        except (httpx.HTTPError, TypeError, ValueError) as exc:
            typer.echo(f"Comparison request for role '{profile.role}' failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        status_line = next(
            (line for line in response.splitlines() if line.startswith("STATUS:")),
            None,
        )
        if status_line is None or "BODY:\n" not in response:
            typer.echo(
                f"Comparison request for role '{profile.role}' returned an unrecognized response.",
                err=True,
            )
            raise typer.Exit(code=1)
        try:
            status_code = int(status_line.split(":", 1)[1].strip())
        except ValueError as exc:
            typer.echo(
                f"Comparison request for role '{profile.role}' returned an invalid HTTP status.",
                err=True,
            )
            raise typer.Exit(code=1) from exc
        body = response.split("BODY:\n", 1)[1]
        content_type = next(
            (
                line.split("content-type", 1)[1].strip(" :,'\"")
                for line in response.splitlines()
                if "content-type" in line.lower()
            ),
            "",
        )
        fingerprints.append((status_code, content_type, hashlib.sha256(body.encode()).hexdigest()))
    typer.echo(f"{profiles[0].role}: HTTP {fingerprints[0][0]}")
    typer.echo(f"{profiles[1].role}: HTTP {fingerprints[1][0]}")
    typer.echo(
        "Responses differ."
        if fingerprints[0] != fingerprints[1]
        else "Responses have the same status, content type, and body digest."
    )


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


@app.command("backup")
def backup_workspace(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file (defaults to the configured data dir)."),
    ] = None,
) -> None:
    """Create a consistent SQLite backup of the current workspace."""
    settings = Settings.load(Path.cwd())
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S-%f")
    destination = output or (
        settings.project_root / settings.data_dir / "backups" / f"bbai-{timestamp}.db"
    )
    try:
        backup_path = create_database_backup(settings.db_path, destination)
    except BackupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Workspace database backed up to {backup_path}")
    typer.echo("Authentication secrets in the system keyring are not included.")


@app.command("restore")
def restore_workspace(
    backup_file: Annotated[Path, typer.Argument(help="SQLite backup file to restore.")],
    replace: Annotated[
        bool,
        typer.Option(
            "--replace",
            help="Replace the current database after saving it as a pre-restore backup.",
        ),
    ] = False,
) -> None:
    """Restore a workspace database from a backup file."""
    settings = Settings.load(Path.cwd())
    try:
        restored_path, previous_backup = restore_database_backup(
            backup_file,
            settings.db_path,
            replace_existing=replace,
        )
    except BackupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Workspace database restored to {restored_path}")
    if previous_backup is not None:
        typer.echo(f"Previous database preserved at {previous_backup}")
    typer.echo("Authentication secrets in the system keyring are not included.")


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
    semantic: bool = typer.Option(
        False, "--semantic", help="Rank local artifacts with Ollama embeddings."
    ),
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
        if semantic:
            corpus = service.search_corpus(target_name=target_name or None)
            ranked = rank_semantically(
                query,
                corpus,
                base_url=settings.ollama.base_url,
                model=settings.ollama.default_model,
                timeout_seconds=settings.ollama.timeout_seconds,
            )
            results = [
                {
                    **item,
                    "type": item["artifact_type"],
                    "id": item["artifact_id"],
                    "target": item["target_name"],
                    "snippet": str(item["body"])[:180],
                }
                for item in ranked
                if (not artifact_type or item["artifact_type"] == artifact_type)
                and (session_id is None or item["session_id"] == session_id)
                and (not status or item["status"] == status)
                and (not severity or item["severity"] == severity)
            ][:limit]
        else:
            results = service.search_artifacts(
                query,
                target_name=target_name or None,
                artifact_type=artifact_type or None,
                session_id=session_id,
                status=status or None,
                severity=severity or None,
                limit=limit,
            )
    except (ValueError, RuntimeError) as exc:
        typer.echo(f"Search failed: {exc}", err=True)
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


@app.command("search-evaluate")
def evaluate_search(
    dataset_path: Path = typer.Argument(  # noqa: B008
        ..., help="JSON dataset with query/relevant artifact IDs."
    ),
    strategy: str = typer.Option("fts", "--strategy", help="fts or semantic."),
    k: int = typer.Option(5, "--k", min=1, max=100),
) -> None:
    if strategy not in {"fts", "semantic"}:
        typer.echo("--strategy must be 'fts' or 'semantic'.", err=True)
        raise typer.Exit(code=2)
    try:
        if dataset_path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Evaluation datasets are limited to 4 MiB")
        dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
        if not isinstance(dataset, list) or not dataset:
            raise ValueError("Evaluation dataset must be a non-empty JSON array")
        settings = Settings.load(Path.cwd())
        service = ProjectService(str(settings.db_path))
        corpus = service.search_corpus(limit=10000) if strategy == "semantic" else []
        metrics: list[dict[str, float]] = []
        for case in dataset:
            if (
                not isinstance(case, dict)
                or not isinstance(case.get("query"), str)
                or not isinstance(case.get("relevant"), list)
            ):
                raise ValueError(  # noqa: TRY004
                    "Each case must contain a query string and relevant ID list"
                )
            started = time.perf_counter()
            if strategy == "semantic":
                ranked = rank_semantically(
                    case["query"],
                    corpus,
                    base_url=settings.ollama.base_url,
                    model=settings.ollama.default_model,
                    timeout_seconds=settings.ollama.timeout_seconds,
                )
                keys = [(item["artifact_type"], item["artifact_id"]) for item in ranked[:k]]
            else:
                ranked = service.search_artifacts(case["query"], limit=100)
                keys = [(item["type"], item["id"]) for item in ranked[:k]]
            elapsed_ms = (time.perf_counter() - started) * 1000
            relevant = {
                (item.get("type"), item.get("id"))
                for item in case["relevant"]
                if isinstance(item, dict)
            }
            hits = [index for index, key in enumerate(keys, start=1) if key in relevant]
            metrics.append(
                {
                    "precision_at_k": len(hits) / k,
                    "recall_at_k": len(set(keys) & relevant) / len(relevant) if relevant else 0.0,
                    "reciprocal_rank": 1 / hits[0] if hits else 0.0,
                    "latency_ms": elapsed_ms,
                }
            )
        averages = {
            key: sum(item[key] for item in metrics) / len(metrics)
            for key in ("precision_at_k", "recall_at_k", "reciprocal_rank", "latency_ms")
        }
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        typer.echo(f"Search evaluation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        json.dumps({"strategy": strategy, "k": k, "queries": len(metrics), **averages}, indent=2)
    )


@app.command("metrics")
def show_metrics(
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
) -> None:
    settings = Settings.load(Path.cwd())
    selected_target = target_name or settings.active_target
    if not selected_target:
        typer.echo("Select a target or pass --target.", err=True)
        raise typer.Exit(code=1)
    service = ProjectService(str(settings.db_path))
    try:
        context = service.get_context_data(target_name=selected_target)
        executions = service.list_tool_executions(target_name=selected_target)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    context_chars = sum(len(value) for value in context.values())
    durations = [
        duration for item in executions if isinstance(duration := item.get("duration_ms"), int)
    ]
    summary = {
        "target": selected_target,
        "context_characters": context_chars,
        "estimated_context_tokens": math.ceil(context_chars / 4),
        "tool_executions": len(executions),
        "tool_duration_ms_total": sum(durations),
        "tool_duration_ms_average": round(sum(durations) / len(durations), 2) if durations else 0,
        "model_tokens_and_cost": "unavailable: Ollama usage is not persisted",
    }
    typer.echo(json.dumps(summary, ensure_ascii=False, indent=2))


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


@_session_app.command("labels")
def set_session_labels(
    session_id: int = typer.Argument(..., help="Numeric session ID."),
    labels: list[str] = typer.Option(  # noqa: B008
        [], "--label", help="Label to assign; repeat as needed."
    ),
) -> None:
    try:
        ProjectService(str(Settings.load(Path.cwd()).db_path)).update_session_labels(
            session_id,
            labels,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Labels updated for S-{session_id:03d}")


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
        labels = f" ({', '.join(session['labels'])})" if session["labels"] else ""
        typer.echo(
            f"- S-{session['id']:03d} [{session['status']}] {session['title']}{labels}{active}"
        )


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
        f"Target: {session['target']} | Status: {session['status']}\n"
        f"Labels: {', '.join(session['labels']) or 'none'}"
    )
    for note in session["notes"]:
        typer.echo(f"[note] {note['content']}")
    for event in session["events"]:
        typer.echo(f"[{event['type']}] {event['content']}")


@_session_app.command("export")
def export_session(
    session_id: int = typer.Argument(..., help="Numeric session ID."),
    output_path: Path = typer.Option(  # noqa: B008
        ..., "--output", "-o", help="Destination JSON file."
    ),
) -> None:
    try:
        data = ProjectService(str(Settings.load(Path.cwd()).db_path)).get_session(session_id)
        output = json.dumps(data, ensure_ascii=False, indent=2, default=_json_default) + "\n"
        atomic_write_private(output_path.expanduser().resolve(), output)
    except (OSError, ValueError) as exc:
        typer.echo(f"Unable to export session: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Session S-{session_id:03d} exported to {output_path.expanduser().resolve()}")


@_session_app.command("prune")
def prune_sessions(
    older_than_days: int = typer.Option(..., "--older-than-days", min=1),
    target_name: str = typer.Option("", "--target", "-t"),
    status: str = typer.Option("closed", "--status", help="Only closed or paused sessions."),
    apply: bool = typer.Option(False, "--apply", help="Delete the matching sessions."),
) -> None:
    if status not in {"closed", "paused"}:
        typer.echo("Retention can only prune closed or paused sessions.", err=True)
        raise typer.Exit(code=2)
    settings = Settings.load(Path.cwd())
    service = ProjectService(str(settings.db_path))
    cutoff = datetime.now(UTC).replace(microsecond=0) - timedelta(days=older_than_days)
    target_filter = target_name or settings.active_target
    try:
        sessions = service.list_sessions(target_name=target_filter) if target_filter else []
        matching = [
            session
            for session in sessions
            if session["status"] == status and session["updated_at"].replace(tzinfo=UTC) < cutoff
        ]
        if not target_filter:
            typer.echo("Retention requires --target or an active target.", err=True)
            raise typer.Exit(code=1)
        if not apply:
            typer.echo(
                f"{len(matching)} {status} session(s) older than {older_than_days} days "
                "match; rerun with --apply to delete them."
            )
            return
        removed = service.prune_sessions(
            before=cutoff,
            target_name=target_filter,
            statuses=(status,),
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Pruned {len(removed)} session(s); linked research artifacts were retained.")


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
    availability = tool_availability()
    metadata = tool_security_metadata()
    for name, status_value in availability.items():
        policy = metadata[name]
        approval = "approval required" if policy["approval_required"] else "no approval"
        typer.echo(
            f"- {name}: {status_value} "
            f"[{policy['activity']}, {policy['risk']} risk, {approval}, "
            f"{policy['permission']}, "
            f"timeout <= {policy['timeout_limit_seconds']}s, "
            f"output <= {policy['output_limit_chars']} chars]"
        )


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
    except (httpx.HTTPError, ValueError, TypeError) as exc:
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
            role=str(profile_data["role"]),
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
    policy = ScopePolicy(
        allowed_tools=frozenset(tools),
        approval_required=False,
        tool_approval_required={name: tool.approval_required for name, tool in tools.items()},
    )
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
                execution_status: ExecutionStatus
                if dry_run:
                    result = "Dry run: tool was not executed."
                    execution_status = "dry_run"
                    approved = False
                elif policy.requires_approval(call.name) and not typer.confirm(
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
                duration_ms = round((time.monotonic() - started) * 1000)
                service.add_tool_execution(
                    target_name=selected_target,
                    tool_name=call.name,
                    arguments=safe_arguments,
                    status=execution_status,
                    approved=approved,
                    output=result if execution_status == "succeeded" else None,
                    error=result if execution_status in {"failed", "denied"} else None,
                    duration_ms=duration_ms,
                    session_id=selected_session_id,
                )
                try:
                    append_tool_audit_event(
                        settings.project_root / settings.data_dir / "audit.jsonl",
                        tool_name=call.name,
                        status=execution_status,
                        approved=approved,
                        duration_ms=duration_ms,
                    )
                except OSError as exc:
                    raise RuntimeError(
                        "Tool execution was recorded in the database, but the audit log "
                        "could not be written. Check workspace directory permissions "
                        "before continuing."
                    ) from exc
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
    except (httpx.HTTPError, ValueError, TypeError) as exc:
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
    template_path: Annotated[
        Path | None,
        typer.Option("--template", help="Markdown template with $title/$summary/... placeholders."),
    ] = None,
    include_drafts: bool = typer.Option(
        False, "--include-drafts", help="Explicitly include findings not yet accepted."
    ),
) -> None:
    if output_format not in {"markdown", "json"}:
        typer.echo("Format must be 'markdown' or 'json'.", err=True)
        raise typer.Exit(code=1)
    if template_path is not None and output_format != "markdown":
        typer.echo("--template can only be used with Markdown output.", err=True)
        raise typer.Exit(code=2)
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
                if profile["role"] != "anonymous":
                    payload = store.get(str(profile["secret_ref"]))
                    secrets.extend(payload.values())
    except (KeyringError, ValueError) as exc:
        typer.echo(f"Unable to verify report redaction: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _redact_report_data(findings, secrets)
    if output_format == "json":
        rendered = json.dumps(findings, ensure_ascii=False, indent=2)
    elif template_path is not None:
        try:
            template = Template(template_path.expanduser().read_text(encoding="utf-8"))
            rendered = "\n\n---\n\n".join(
                template.substitute(_report_template_values(finding)) for finding in findings
            )
        except (OSError, KeyError, ValueError) as exc:
            typer.echo(f"Unable to render report template: {exc}", err=True)
            raise typer.Exit(code=1) from exc
    else:
        rendered = _render_markdown_report(findings)
    rendered = redact_secrets(rendered, secrets)
    if output_path:
        output_path = output_path.expanduser().resolve()
        try:
            atomic_write_private(output_path, rendered + "\n")
        except OSError as exc:
            typer.echo(f"Unable to write report to '{output_path}': {exc}", err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(f"Report written to {output_path}")
    else:
        typer.echo(rendered)


@_workspace_app.command("export")
def export_workspace_command(
    output_path: Path = typer.Argument(  # noqa: B008
        ..., help="Destination .bbai.zip file."
    ),
) -> None:
    settings = Settings.load(Path.cwd())
    try:
        archive = export_workspace(settings.db_path, output_path)
    except BackupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Workspace exported to {archive}")
    typer.echo(
        "The archive includes the SQLite database only; config and keyring secrets are excluded."
    )


@_workspace_app.command("import")
def import_workspace_command(
    archive_path: Path = typer.Argument(  # noqa: B008
        ..., help="Portable workspace .bbai.zip archive."
    ),
    replace: bool = typer.Option(
        False,
        "--replace",
        help="Replace the current database after preserving it as a pre-restore backup.",
    ),
) -> None:
    settings = Settings.load(Path.cwd())
    try:
        database, previous = import_workspace(
            archive_path,
            settings.db_path,
            replace_existing=replace,
        )
    except BackupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Workspace database imported to {database}")
    if previous is not None:
        typer.echo(f"Previous database preserved at {previous}")
    typer.echo("Configuration and system keyring secrets are not imported.")


@app.command("import-results")
def import_results(
    input_path: Path = typer.Argument(  # noqa: B008
        ..., help="Scanner output file."
    ),
    input_format: str = typer.Option(..., "--format", help="nuclei-jsonl or sarif."),
    target_name: str = typer.Option("", "--target", "-t", help="Target override."),
    session_id: int | None = typer.Option(None, "--session", help="Optional active session ID."),
) -> None:
    if input_format not in {"nuclei-jsonl", "sarif"}:
        typer.echo("--format must be 'nuclei-jsonl' or 'sarif'.", err=True)
        raise typer.Exit(code=2)
    try:
        if input_path.stat().st_size > MAX_IMPORT_BYTES:
            raise ValueError("Import files are limited to 32 MiB")
        content = input_path.read_text(encoding="utf-8")
        settings = Settings.load(Path.cwd())
        selected_target = target_name or settings.active_target
        if not selected_target:
            raise ValueError("Select a target with `bbai target use` or pass --target.")
        service = ProjectService(str(settings.db_path))
        target = service.get_target(selected_target)
        if target is None:
            raise ValueError(f"Target '{selected_target}' does not exist")
        if not target["scope"]:
            raise ValueError("Target must have an explicit scope before importing scanner results.")
        imported = (
            parse_nuclei_jsonl(content, str(target["scope"]))
            if input_format == "nuclei-jsonl"
            else parse_sarif(content, str(target["scope"]))
        )
        if session_id is not None:
            session = service.get_session(session_id)
            if session["target"] != selected_target or session["status"] != "active":
                raise ValueError("Selected session must be active and belong to this target.")
        imported_findings: list[ImportedFindingInput] = []
        for result in imported:
            location_text = f"\nLocation: {result.location}" if result.location else ""
            imported_findings.append(
                {
                    "title": result.title,
                    "summary": result.summary,
                    "severity": result.severity,
                    "evidence_source": f"import:{result.source}:{result.title}",
                    "evidence_kind": f"scanner-{result.source}",
                    "evidence_content": f"{result.summary}{location_text}",
                }
            )
        service.add_imported_findings(
            target_name=selected_target,
            imported=imported_findings,
            session_id=session_id,
        )
    except (OSError, UnicodeError, SQLAlchemyError, ValueError) as exc:
        typer.echo(f"Unable to import scanner results: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Imported {len(imported)} scoped result(s) as draft findings.")


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


def _report_template_values(finding: FindingData) -> dict[str, str]:
    evidence = "\n\n".join(
        f"- {item['source']} ({item['kind']}):\n  {item['content']}" for item in finding["evidence"]
    )
    return {
        "id": str(finding["id"]),
        "target": str(finding["target"]),
        "title": str(finding["title"]),
        "summary": str(finding["summary"]),
        "severity": str(finding["severity"]),
        "confidence": str(finding["confidence"]),
        "impact": str(finding["impact"]),
        "reproduction": str(finding["reproduction"]),
        "remediation": str(finding["remediation"]),
        "status": str(finding["status"]),
        "session": str(finding["session_title"] or ""),
        "evidence": evidence,
    }


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


if __name__ == "__main__":
    app()
