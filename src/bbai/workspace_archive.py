from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path

from bbai.backup import BackupError, create_database_backup, restore_database_backup
from bbai.filesystem import create_private_directory

MANIFEST_NAME = "manifest.json"
DATABASE_NAME = "workspace.sqlite3"
ARCHIVE_VERSION = 1
MAX_DATABASE_BYTES = 512 * 1024 * 1024


def export_workspace(database_path: Path, destination: Path) -> Path:
    database = database_path.expanduser().resolve()
    archive_path = destination.expanduser().resolve()
    if archive_path.exists():
        raise BackupError(f"Workspace export already exists: {archive_path}")
    create_private_directory(archive_path.parent)
    temporary_archive: Path | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="bbai-export-") as temp_directory:
            snapshot = Path(temp_directory) / DATABASE_NAME
            create_database_backup(database, snapshot)
            digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
            manifest = {
                "format": "bbai-workspace",
                "version": ARCHIVE_VERSION,
                "database": DATABASE_NAME,
                "sha256": digest,
            }
            with tempfile.NamedTemporaryFile(
                prefix=f".{archive_path.name}.",
                suffix=".tmp",
                dir=archive_path.parent,
                delete=False,
            ) as handle:
                temporary_archive = Path(handle.name)
            with zipfile.ZipFile(
                temporary_archive, "w", compression=zipfile.ZIP_DEFLATED
            ) as bundle:
                bundle.write(snapshot, DATABASE_NAME)
                bundle.writestr(MANIFEST_NAME, json.dumps(manifest, separators=(",", ":")))
        if os.name == "posix":
            temporary_archive.chmod(0o600)
        os.replace(temporary_archive, archive_path)
        return archive_path
    except (OSError, zipfile.BadZipFile, BackupError) as exc:
        if temporary_archive is not None:
            temporary_archive.unlink(missing_ok=True)
        if isinstance(exc, BackupError):
            raise
        raise BackupError(f"Unable to export workspace: {exc}") from exc


def import_workspace(
    archive_path: Path,
    database_path: Path,
    *,
    replace_existing: bool = False,
) -> tuple[Path, Path | None]:
    source = archive_path.expanduser().resolve()
    target = database_path.expanduser().resolve()
    if not source.is_file():
        raise BackupError(f"Workspace export does not exist: {source}")
    try:
        with zipfile.ZipFile(source) as bundle:
            names = bundle.namelist()
            if sorted(names) != sorted((MANIFEST_NAME, DATABASE_NAME)):
                raise BackupError("Workspace archive must contain exactly a manifest and database.")
            manifest_info = bundle.getinfo(MANIFEST_NAME)
            database_info = bundle.getinfo(DATABASE_NAME)
            if _is_symlink(manifest_info) or _is_symlink(database_info):
                raise BackupError("Workspace archive cannot contain symbolic links.")
            if database_info.file_size > MAX_DATABASE_BYTES:
                raise BackupError("Workspace database exceeds the 512 MiB import limit.")
            if manifest_info.file_size > 4096 or database_info.flag_bits & 0x1:
                raise BackupError("Workspace archive manifest is too large or member is encrypted.")
            manifest_value = json.loads(bundle.read(MANIFEST_NAME))
            if (
                not isinstance(manifest_value, dict)
                or manifest_value.get("format") != "bbai-workspace"
                or manifest_value.get("version") != ARCHIVE_VERSION
                or manifest_value.get("database") != DATABASE_NAME
            ):
                raise BackupError("Unsupported or invalid workspace archive manifest.")
            with tempfile.TemporaryDirectory(prefix="bbai-import-") as temp_directory:
                staged_database = Path(temp_directory) / DATABASE_NAME
                digest_builder = hashlib.sha256()
                with bundle.open(DATABASE_NAME) as member, staged_database.open("wb") as output:
                    total = 0
                    while chunk := member.read(1024 * 1024):
                        total += len(chunk)
                        if total > MAX_DATABASE_BYTES:
                            raise BackupError("Workspace database exceeds the import size limit.")
                        digest_builder.update(chunk)
                        output.write(chunk)
                if digest_builder.hexdigest() != manifest_value.get("sha256"):
                    raise BackupError("Workspace archive checksum does not match its database.")
                return restore_database_backup(
                    staged_database,
                    target,
                    replace_existing=replace_existing,
                )
    except (OSError, json.JSONDecodeError, zipfile.BadZipFile, KeyError) as exc:
        raise BackupError(f"Unable to import workspace archive: {exc}") from exc


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000
