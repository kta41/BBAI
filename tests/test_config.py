import os
from pathlib import Path

from bbai.config import Settings
from bbai.db import init_db


def test_loads_default_settings(tmp_path: Path) -> None:
    config_path = tmp_path / ".bbai.toml"
    config_path.write_text(
        'project_name = "bbai"\n'
        'data_dir = ".bbai"\n\n'
        '[ollama]\n'
        'base_url = "http://localhost:11434"\n'
        'default_model = "llama3.1"\n'
        'timeout_seconds = 60\n',
        encoding="utf-8",
    )

    settings = Settings.load(tmp_path)

    assert settings.project_name == "bbai"
    assert settings.ollama.base_url == "http://localhost:11434"
    assert settings.ollama.default_model == "llama3.1"
    assert settings.db_path == tmp_path / ".bbai" / "bbai.db"


def test_save_creates_config_file(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path)

    config_path = settings.save()

    assert config_path.exists()
    assert "[ollama]" in config_path.read_text(encoding="utf-8")
    if os.name == "posix":
        assert config_path.stat().st_mode & 0o777 == 0o600


def test_database_files_and_data_directory_are_private(tmp_path: Path) -> None:
    db_path = tmp_path / ".bbai" / "bbai.db"
    init_db(str(db_path))
    if os.name == "posix":
        assert db_path.parent.stat().st_mode & 0o777 == 0o700
        assert db_path.stat().st_mode & 0o777 == 0o600


def test_save_and_load_active_target(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, active_target="example.com")
    settings.save()

    loaded = Settings.load(tmp_path)

    assert loaded.active_target == "example.com"
