from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from bbai.backup import BackupError
from bbai.services.project_service import ProjectService
from bbai.workspace_archive import export_workspace, import_workspace


def test_workspace_archive_round_trip_and_explicit_replace(tmp_path: Path) -> None:
    source_db = tmp_path / "source" / ".bbai" / "bbai.db"
    source_db.parent.mkdir(parents=True)
    source = ProjectService(str(source_db))
    source.add_target(name="example.com", scope="example.com")
    archive = export_workspace(source_db, tmp_path / "portable.bbai.zip")

    destination_db = tmp_path / "destination" / ".bbai" / "bbai.db"
    destination_db.parent.mkdir(parents=True)
    destination = ProjectService(str(destination_db))
    destination.add_target(name="old.example", scope="old.example")
    with pytest.raises(BackupError, match="--replace"):
        import_workspace(archive, destination_db)
    restored, previous = import_workspace(archive, destination_db, replace_existing=True)

    assert restored == destination_db.resolve()
    assert previous is not None
    assert [item["name"] for item in ProjectService(str(restored)).list_targets()] == [
        "example.com"
    ]
    assert [item["name"] for item in ProjectService(str(previous)).list_targets()] == [
        "old.example"
    ]


def test_workspace_import_rejects_bad_checksum_and_unexpected_members(tmp_path: Path) -> None:
    source_db = tmp_path / "bbai.db"
    service = ProjectService(str(source_db))
    service.add_target(name="example.com", scope="example.com")
    valid = export_workspace(source_db, tmp_path / "valid.zip")

    with zipfile.ZipFile(valid) as original:
        manifest = json.loads(original.read("manifest.json"))
        manifest["sha256"] = "0" * 64
        checksum_bad = tmp_path / "bad-checksum.zip"
        with zipfile.ZipFile(checksum_bad, "w") as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("workspace.sqlite3", original.read("workspace.sqlite3"))
        unexpected = tmp_path / "unexpected.zip"
        with zipfile.ZipFile(unexpected, "w") as archive:
            archive.writestr("manifest.json", original.read("manifest.json"))
            archive.writestr("workspace.sqlite3", original.read("workspace.sqlite3"))
            archive.writestr("../outside", "no")

    destination = tmp_path / "destination.db"
    with pytest.raises(BackupError, match="checksum"):
        import_workspace(checksum_bad, destination)
    with pytest.raises(BackupError, match="exactly"):
        import_workspace(unexpected, destination)
