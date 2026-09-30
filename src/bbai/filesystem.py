from __future__ import annotations

import os
import tempfile
from pathlib import Path


def secure_private_directory(path: Path) -> Path:
    create_private_directory(path)
    if os.name == "posix":
        path.chmod(0o700)
    return path


def create_private_directory(path: Path) -> Path:
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            if not directory.is_dir():
                raise
        if os.name == "posix":
            directory.chmod(0o700)
    if not path.is_dir():
        raise NotADirectoryError(f"Expected a directory at '{path}'")
    return path


def atomic_write_private(path: Path, content: str, *, secure_parent: bool = False) -> Path:
    if secure_parent:
        secure_private_directory(path.parent)
    else:
        create_private_directory(path.parent)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        return path
    except OSError:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def secure_private_file(path: Path) -> Path:
    if os.name == "posix":
        path.chmod(0o600)
    return path
