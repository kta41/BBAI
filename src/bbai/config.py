from __future__ import annotations

import json
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field


class OllamaSettings(BaseModel):
    base_url: str = Field(default="http://localhost:11434")
    default_model: str = Field(default="llama3.1")
    timeout_seconds: int = Field(default=60)


class Settings(BaseModel):
    project_name: str = Field(default="bbai")
    project_root: Path = Field(default=Path.cwd())
    data_dir: Path = Field(default=Path(".bbai"))
    active_target: str | None = Field(default=None)
    active_session_id: int | None = Field(default=None)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)

    @property
    def db_path(self) -> Path:
        return self.project_root / self.data_dir / "bbai.db"

    @classmethod
    def load(cls, project_root: Path | str | None = None) -> Settings:
        root = Path(project_root) if project_root is not None else Path.cwd()
        config_file = root / ".bbai.toml"
        if not config_file.exists():
            return cls(project_root=root)

        with config_file.open("rb") as handle:
            data = tomllib.load(handle)
        payload: dict[str, object] = {"project_root": root}
        if "project_name" in data:
            payload["project_name"] = data["project_name"]
        if "data_dir" in data:
            payload["data_dir"] = data["data_dir"]
        if "active_target" in data:
            payload["active_target"] = data["active_target"]
        if "active_session_id" in data:
            payload["active_session_id"] = data["active_session_id"]
        if "ollama" in data:
            payload["ollama"] = data["ollama"]
        return cls.model_validate(payload)

    def save(self) -> Path:
        config_file = self.project_root / ".bbai.toml"
        self.project_root.mkdir(parents=True, exist_ok=True)
        active_session = (
            f"active_session_id = {self.active_session_id}\n"
            if self.active_session_id is not None
            else ""
        )
        config_file.write_text(
            f'project_name = "{self.project_name}"\n'
            f'data_dir = "{self.data_dir.as_posix()}"\n\n'
            f"active_target = {json.dumps(self.active_target or '')}\n\n"
            f"{active_session}\n"
            "[ollama]\n"
            f'base_url = "{self.ollama.base_url}"\n'
            f'default_model = "{self.ollama.default_model}"\n'
            f'timeout_seconds = {self.ollama.timeout_seconds}\n',
            encoding="utf-8",
        )
        return config_file
