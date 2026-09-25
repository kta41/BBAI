from __future__ import annotations

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


def get_engine(db_path: str) -> Engine:
    return create_engine(f"sqlite:///{db_path}", future=True)


def get_session_factory(db_path: str) -> sessionmaker[Session]:
    engine = get_engine(db_path)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db(db_path: str) -> None:
    engine = get_engine(db_path)
    Base.metadata.create_all(bind=engine)
    _migrate_phase_two_columns(engine)


def _migrate_phase_two_columns(engine: Engine) -> None:
    migrations = {
        "observations": (
            ("evidence_id", "INTEGER REFERENCES evidence(id)"),
            ("tool_execution_id", "INTEGER REFERENCES tool_executions(id)"),
        ),
        "hypotheses": (
            ("confidence", "VARCHAR(20) NOT NULL DEFAULT 'unknown'"),
            ("evidence_id", "INTEGER REFERENCES evidence(id)"),
            ("observation_id", "INTEGER REFERENCES observations(id)"),
        ),
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, columns in migrations.items():
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, definition in columns:
                if column_name not in existing:
                    connection.execute(
                        text(f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}" {definition}')
                    )
