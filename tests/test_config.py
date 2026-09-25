from pathlib import Path

from bbai.config import Settings


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


def test_save_and_load_active_target(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, active_target="example.com")
    settings.save()

    loaded = Settings.load(tmp_path)

    assert loaded.active_target == "example.com"
