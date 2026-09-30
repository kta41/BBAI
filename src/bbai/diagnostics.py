from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal, TypedDict

import httpx
import keyring
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from keyring.errors import KeyringError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from bbai.config import Settings
from bbai.db import get_engine

CheckStatus = Literal["ok", "warning", "error"]


class Diagnostic(TypedDict):
    name: str
    status: CheckStatus
    detail: str


OPTIONAL_TOOLS = ("subfinder", "ffuf", "gau", "katana", "nuclei")


def run_diagnostics(settings: Settings) -> list[Diagnostic]:
    checks: list[Diagnostic] = []
    config_file = settings.project_root / ".bbai.toml"
    checks.append(
        {
            "name": "Workspace",
            "status": "ok" if config_file.is_file() else "warning",
            "detail": (
                f"Configuration: {config_file}"
                if config_file.is_file()
                else "Workspace is not initialized; run `bbai init`."
            ),
        }
    )
    checks.extend(_database_checks(settings))
    checks.extend(_ollama_checks(settings))
    checks.append(_keyring_check())
    checks.extend(_tool_checks())
    if settings.active_target:
        if not settings.db_path.is_file():
            checks.append(
                {
                    "name": "Active target",
                    "status": "warning",
                    "detail": "Database does not exist, so the configured target cannot be checked.",
                }
            )
            return checks
        engine = get_engine(str(settings.db_path))
        try:
            with engine.connect() as connection:
                row = (
                    connection.execute(
                        text("SELECT name, scope FROM targets WHERE name = :name"),
                        {"name": settings.active_target},
                    )
                    .mappings()
                    .one_or_none()
                )
        except SQLAlchemyError as exc:
            checks.append(
                {
                    "name": "Active target",
                    "status": "error",
                    "detail": f"Unable to load active target: {exc}",
                }
            )
        else:
            if row is None:
                checks.append(
                    {
                        "name": "Active target",
                        "status": "error",
                        "detail": f"Configured target '{settings.active_target}' does not exist.",
                    }
                )
            elif not row["scope"]:
                checks.append(
                    {
                        "name": "Active target",
                        "status": "warning",
                        "detail": "Target has no scope; investigation tools will be disabled.",
                    }
                )
            else:
                checks.append(
                    {
                        "name": "Active target",
                        "status": "ok",
                        "detail": f"{row['name']} with an approved scope is selected.",
                    }
                )
        finally:
            engine.dispose()
    else:
        checks.append(
            {
                "name": "Active target",
                "status": "warning",
                "detail": "No target selected; set one with `bbai target use <name>`.",
            }
        )
    return checks


def _database_checks(settings: Settings) -> list[Diagnostic]:
    if not settings.db_path.is_file():
        return [
            {
                "name": "Database",
                "status": "warning",
                "detail": f"{settings.db_path} does not exist; run `bbai init`.",
            }
        ]
    checks: list[Diagnostic] = []
    engine = get_engine(str(settings.db_path))
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            checks.append(
                {
                    "name": "Database",
                    "status": "ok",
                    "detail": f"SQLite is readable: {settings.db_path}",
                }
            )
            has_version_table = connection.execute(
                text(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alembic_version'"
                )
            ).scalar_one_or_none()
            current_revision = (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                if has_version_table
                else None
            )
            head = _migration_head()
            checks.append(
                {
                    "name": "Migrations",
                    "status": "ok" if current_revision == head else "warning",
                    "detail": (
                        f"Database revision {current_revision} is current."
                        if current_revision == head
                        else f"Database revision {current_revision or 'unversioned'}; "
                        f"expected {head}. Open the workspace to apply migrations."
                    ),
                }
            )
            connection.exec_driver_sql(
                "CREATE VIRTUAL TABLE temp.bbai_doctor_fts USING fts5(value)"
            )
            connection.exec_driver_sql("DROP TABLE temp.bbai_doctor_fts")
            checks.append(
                {
                    "name": "SQLite FTS5",
                    "status": "ok",
                    "detail": "FTS5 virtual tables are available.",
                }
            )
    except (OSError, SQLAlchemyError, CommandError, ValueError) as exc:
        checks.append(
            {
                "name": "Database",
                "status": "error",
                "detail": f"Database or FTS5 check failed: {exc}",
            }
        )
    finally:
        engine.dispose()
    return checks


def _migration_head() -> str:
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).parent / "migrations"),
    )
    return str(ScriptDirectory.from_config(config).get_current_head())


def _ollama_checks(settings: Settings) -> list[Diagnostic]:
    try:
        response = httpx.get(
            f"{settings.ollama.base_url.rstrip('/')}/api/tags",
            timeout=min(settings.ollama.timeout_seconds, 3),
        )
        response.raise_for_status()
        data = response.json()
        models = data.get("models", []) if isinstance(data, dict) else []
        if not isinstance(models, list):
            models = []
        names = {str(model.get("name", "")) for model in models if isinstance(model, dict)}
    except (httpx.HTTPError, ValueError) as exc:
        return [
            {
                "name": "Ollama",
                "status": "warning",
                "detail": f"Cannot reach {settings.ollama.base_url}: {exc}",
            }
        ]
    model_found = any(
        name == settings.ollama.default_model
        or name.split(":", 1)[0] == settings.ollama.default_model.split(":", 1)[0]
        for name in names
    )
    return [
        {
            "name": "Ollama",
            "status": "ok",
            "detail": f"API reachable at {settings.ollama.base_url}.",
        },
        {
            "name": "Configured model",
            "status": "ok" if model_found else "warning",
            "detail": (
                f"{settings.ollama.default_model} is available."
                if model_found
                else f"{settings.ollama.default_model} is not listed by Ollama."
            ),
        },
    ]


def _keyring_check() -> Diagnostic:
    try:
        backend = keyring.get_keyring()
        priority = backend.priority
    except (KeyringError, RuntimeError, ImportError) as exc:
        return {
            "name": "Keyring",
            "status": "warning",
            "detail": f"Unable to inspect the system keyring backend: {exc}",
        }
    if isinstance(priority, (int, float)) and priority <= 0:
        return {
            "name": "Keyring",
            "status": "warning",
            "detail": f"No usable secure keyring backend: {type(backend).__name__}.",
        }
    return {
        "name": "Keyring",
        "status": "ok",
        "detail": f"Backend available: {type(backend).__name__}; no secrets were read.",
    }


def _tool_checks() -> list[Diagnostic]:
    checks: list[Diagnostic] = []
    for tool in OPTIONAL_TOOLS:
        executable = shutil.which(tool)
        checks.append(
            {
                "name": tool,
                "status": "ok" if executable else "warning",
                "detail": (
                    f"Found at {executable}."
                    if executable
                    else "Optional binary not found in PATH."
                ),
            }
        )
    return checks
