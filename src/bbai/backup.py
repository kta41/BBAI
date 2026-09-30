from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path

from bbai.filesystem import create_private_directory


class BackupError(RuntimeError):
    pass


def create_database_backup(database_path: Path, destination: Path) -> Path:
    source = database_path.expanduser().resolve()
    target = destination.expanduser().resolve()
    if source == target:
        raise BackupError("Backup destination must differ from the workspace database.")
    if target.exists():
        raise BackupError(f"Backup destination already exists: {target}")

    _validate_database(source)
    temporary: Path | None = None
    try:
        create_private_directory(target.parent)
        temporary = _temporary_path(target.parent, target.name)
        _copy_database(source, temporary)
        _validate_database(temporary)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except (OSError, sqlite3.Error, BackupError) as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if isinstance(exc, BackupError):
            raise
        raise BackupError(f"Unable to create database backup: {exc}") from exc
    return target


def restore_database_backup(
    backup_path: Path,
    database_path: Path,
    *,
    replace_existing: bool = False,
) -> tuple[Path, Path | None]:
    source = backup_path.expanduser().resolve()
    target = database_path.expanduser().resolve()
    if source == target:
        raise BackupError("Restore source must differ from the workspace database.")
    _validate_database(source)
    if target.exists() and not replace_existing:
        raise BackupError(
            f"Workspace database already exists: {target}. "
            "Use --replace to preserve it as a pre-restore backup and continue."
        )

    temporary: Path | None = None
    previous_backup: Path | None = None
    try:
        create_private_directory(target.parent)
        temporary = _temporary_path(target.parent, target.name)
        _copy_database(source, temporary)
        _validate_database(temporary)
        os.chmod(temporary, 0o600)
        if target.exists():
            previous_backup = _next_restore_backup_path(target)
            create_database_backup(target, previous_backup)
        os.replace(temporary, target)
    except (OSError, sqlite3.Error, BackupError) as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if isinstance(exc, BackupError):
            raise
        raise BackupError(f"Unable to restore workspace database: {exc}") from exc
    return target, previous_backup


def _validate_database(path: Path) -> None:
    if not path.is_file():
        raise BackupError(f"Database file does not exist: {path}")
    try:
        with sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise BackupError(f"Database integrity check failed: {path}")
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if not {"alembic_version", "targets"}.issubset(tables):
                raise BackupError(f"File is not a migrated bbai database: {path}")
    except sqlite3.Error as exc:
        raise BackupError(f"Unable to read SQLite database '{path}': {exc}") from exc


def _copy_database(source: Path, destination: Path) -> None:
    with (
        sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True) as source_connection,
        sqlite3.connect(destination) as destination_connection,
    ):
        source_connection.backup(destination_connection)


def _temporary_path(directory: Path, name: str) -> Path:
    with tempfile.NamedTemporaryFile(
        prefix=f".{name}.",
        suffix=".tmp",
        dir=directory,
        delete=False,
    ) as handle:
        return Path(handle.name)


def _next_restore_backup_path(database_path: Path) -> Path:
    index = 1
    while True:
        candidate = database_path.with_name(
            f"{database_path.name}.pre-restore-{index}.bak"
        )
        if not candidate.exists():
            return candidate
        index += 1
