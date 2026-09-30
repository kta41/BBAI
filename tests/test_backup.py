from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from bbai.backup import BackupError, create_database_backup, restore_database_backup
from bbai.services.project_service import ProjectService


def test_database_backup_and_restore_preserve_both_database_states(tmp_path: Path) -> None:
    database = tmp_path / ".bbai" / "bbai.db"
    database.parent.mkdir()
    service = ProjectService(str(database))
    service.add_target(name="example.com", scope="example.com")

    backup = create_database_backup(database, tmp_path / "backups" / "research.db")
    assert backup.exists()

    service.add_target(name="later.example", scope="later.example")
    with pytest.raises(BackupError, match="Use --replace"):
        restore_database_backup(backup, database)

    restored, previous = restore_database_backup(backup, database, replace_existing=True)
    assert restored == database.resolve()
    assert previous is not None and previous.exists()
    assert [target["name"] for target in ProjectService(str(database)).list_targets()] == [
        "example.com"
    ]
    assert {
        target["name"]
        for target in ProjectService(str(previous)).list_targets()
    } == {"example.com", "later.example"}


def test_backup_and_restore_reject_corrupt_or_unrelated_sqlite_files(tmp_path: Path) -> None:
    database = tmp_path / "bbai.db"
    service = ProjectService(str(database))
    service.add_target(name="example.com", scope="example.com")
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_text("not a SQLite database", encoding="utf-8")

    with pytest.raises(BackupError, match="SQLite database"):
        restore_database_backup(corrupt, database, replace_existing=True)
    with pytest.raises(BackupError, match="migrated bbai database"):
        _write_unrelated_sqlite(tmp_path / "unrelated.db")
        restore_database_backup(tmp_path / "unrelated.db", database, replace_existing=True)

    assert [target["name"] for target in ProjectService(str(database)).list_targets()] == [
        "example.com"
    ]


def _write_unrelated_sqlite(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
