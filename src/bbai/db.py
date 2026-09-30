from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from bbai.filesystem import secure_private_directory, secure_private_file


class Base(DeclarativeBase):
    pass


def get_engine(db_path: str) -> Engine:
    return create_engine(f"sqlite:///{db_path}", future=True)


def get_session_factory(db_path: str) -> sessionmaker[Session]:
    engine = get_engine(db_path)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db(db_path: str) -> None:
    database_path = Path(db_path)
    secure_private_directory(database_path.parent)
    engine = get_engine(str(database_path))
    config = Config()
    config.set_main_option(
        "script_location",
        str(Path(__file__).parent / "migrations"),
    )
    config.attributes["connection"] = engine.connect()
    try:
        command.upgrade(config, "head")
    finally:
        connection = config.attributes["connection"]
        connection.close()
        engine.dispose()
    secure_private_file(database_path)
