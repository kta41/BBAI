from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_fts_search"
down_revision = "0001_adopt_existing_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "search_documents",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("artifact_type", sa.String(30), nullable=False),
        sa.Column("artifact_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("target_name", sa.Text(), nullable=False),
        sa.Column("session_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.UniqueConstraint("artifact_type", "artifact_id", name="uq_search_document_artifact"),
    )
    bind = op.get_bind()
    bind.exec_driver_sql(
        """
        CREATE VIRTUAL TABLE search_index USING fts5(
            artifact_type UNINDEXED,
            artifact_id UNINDEXED,
            target_id UNINDEXED,
            target_name UNINDEXED,
            session_id UNINDEXED,
            status UNINDEXED,
            severity UNINDEXED,
            title,
            body,
            content='search_documents',
            content_rowid='id',
            tokenize='unicode61'
        )
        """
    )
    _create_index_triggers()
    _backfill_documents()
    bind.exec_driver_sql("INSERT INTO search_index(search_index) VALUES ('rebuild')")


def downgrade() -> None:
    bind = op.get_bind()
    for table_name in (
        "targets",
        "evidence",
        "observations",
        "hypotheses",
        "findings",
        "sessions",
        "notes",
        "session_events",
        "search_documents",
    ):
        bind.exec_driver_sql(f"DROP TRIGGER IF EXISTS {table_name}_search_insert")
        bind.exec_driver_sql(f"DROP TRIGGER IF EXISTS {table_name}_search_update")
        bind.exec_driver_sql(f"DROP TRIGGER IF EXISTS {table_name}_search_delete")
    bind.exec_driver_sql("DROP TRIGGER IF EXISTS search_documents_fts_insert")
    bind.exec_driver_sql("DROP TRIGGER IF EXISTS search_documents_fts_update")
    bind.exec_driver_sql("DROP TRIGGER IF EXISTS search_documents_fts_delete")
    bind.exec_driver_sql("DROP TABLE IF EXISTS search_index")
    op.drop_table("search_documents")


def _create_index_triggers() -> None:
    bind = op.get_bind()
    bind.exec_driver_sql(
        """
        CREATE TRIGGER search_documents_fts_insert AFTER INSERT ON search_documents BEGIN
            INSERT INTO search_index(rowid, artifact_type, artifact_id, target_id,
                target_name, session_id, status, severity, title, body)
            VALUES (new.id, new.artifact_type, new.artifact_id, new.target_id,
                new.target_name, new.session_id, new.status, new.severity, new.title, new.body);
        END
        """
    )
    bind.exec_driver_sql(
        """
        CREATE TRIGGER search_documents_fts_update AFTER UPDATE ON search_documents BEGIN
            INSERT INTO search_index(search_index, rowid, artifact_type, artifact_id, target_id,
                target_name, session_id, status, severity, title, body)
            VALUES ('delete', old.id, old.artifact_type, old.artifact_id, old.target_id,
                old.target_name, old.session_id, old.status, old.severity, old.title, old.body);
            INSERT INTO search_index(rowid, artifact_type, artifact_id, target_id,
                target_name, session_id, status, severity, title, body)
            VALUES (new.id, new.artifact_type, new.artifact_id, new.target_id,
                new.target_name, new.session_id, new.status, new.severity, new.title, new.body);
        END
        """
    )
    bind.exec_driver_sql(
        """
        CREATE TRIGGER search_documents_fts_delete AFTER DELETE ON search_documents BEGIN
            INSERT INTO search_index(search_index, rowid, artifact_type, artifact_id, target_id,
                target_name, session_id, status, severity, title, body)
            VALUES ('delete', old.id, old.artifact_type, old.artifact_id, old.target_id,
                old.target_name, old.session_id, old.status, old.severity, old.title, old.body);
        END
        """
    )

    sources = {
        "targets": {
            "type": "target",
            "target_id": "NEW.id",
            "target_name": "NEW.name",
            "session_id": "NULL",
            "status": "NULL",
            "severity": "NULL",
            "title": "NEW.name",
            "body": "coalesce(NEW.description, '') || char(10) || coalesce(NEW.scope, '')",
        },
        "evidence": {
            "type": "evidence",
            "target_id": "NEW.target_id",
            "target_name": "(SELECT name FROM targets WHERE id = NEW.target_id)",
            "session_id": "NEW.session_id",
            "status": "NULL",
            "severity": "NULL",
            "title": "NEW.source",
            "body": "NEW.kind || char(10) || NEW.content",
        },
        "observations": {
            "type": "observation",
            "target_id": "NEW.target_id",
            "target_name": "(SELECT name FROM targets WHERE id = NEW.target_id)",
            "session_id": "NEW.session_id",
            "status": "NULL",
            "severity": "NULL",
            "title": "substr(NEW.summary, 1, 160)",
            "body": "NEW.summary",
        },
        "hypotheses": {
            "type": "hypothesis",
            "target_id": "NEW.target_id",
            "target_name": "(SELECT name FROM targets WHERE id = NEW.target_id)",
            "session_id": "NEW.session_id",
            "status": "NEW.status",
            "severity": "NULL",
            "title": "substr(NEW.statement, 1, 160)",
            "body": "NEW.statement",
        },
        "findings": {
            "type": "finding",
            "target_id": "NEW.target_id",
            "target_name": "(SELECT name FROM targets WHERE id = NEW.target_id)",
            "session_id": "NEW.session_id",
            "status": "NEW.status",
            "severity": "NEW.severity",
            "title": "NEW.title",
            "body": (
                "NEW.summary || char(10) || coalesce(NEW.impact, '') || char(10) || "
                "coalesce(NEW.reproduction, '') || char(10) || coalesce(NEW.remediation, '')"
            ),
        },
        "sessions": {
            "type": "session",
            "target_id": "NEW.target_id",
            "target_name": "(SELECT name FROM targets WHERE id = NEW.target_id)",
            "session_id": "NEW.id",
            "status": "NEW.status",
            "severity": "NULL",
            "title": "NEW.title",
            "body": "''",
        },
        "notes": {
            "type": "note",
            "target_id": "(SELECT target_id FROM sessions WHERE id = NEW.session_id)",
            "target_name": (
                "(SELECT targets.name FROM targets JOIN sessions "
                "ON sessions.target_id = targets.id WHERE sessions.id = NEW.session_id)"
            ),
            "session_id": "NEW.session_id",
            "status": "NULL",
            "severity": "NULL",
            "title": "'Session note'",
            "body": "NEW.content",
        },
        "session_events": {
            "type": "session_event",
            "target_id": "(SELECT target_id FROM sessions WHERE id = NEW.session_id)",
            "target_name": (
                "(SELECT targets.name FROM targets JOIN sessions "
                "ON sessions.target_id = targets.id WHERE sessions.id = NEW.session_id)"
            ),
            "session_id": "NEW.session_id",
            "status": "NULL",
            "severity": "NULL",
            "title": "NEW.event_type",
            "body": "NEW.content || char(10) || coalesce(NEW.details, '')",
        },
    }
    for table_name, fields in sources.items():
        _create_source_triggers(table_name, fields)


def _create_source_triggers(table_name: str, fields: dict[str, str]) -> None:
    bind = op.get_bind()
    column_names = (
        "artifact_type",
        "artifact_id",
        "target_id",
        "target_name",
        "session_id",
        "status",
        "severity",
        "title",
        "body",
    )
    expressions = (
        f"'{fields['type']}'",
        "NEW.id",
        fields["target_id"],
        fields["target_name"],
        fields["session_id"],
        fields["status"],
        fields["severity"],
        fields["title"],
        fields["body"],
    )
    insert = (
        f"INSERT INTO search_documents ({', '.join(column_names)}) "
        f"VALUES ({', '.join(expressions)}) "
        "ON CONFLICT(artifact_type, artifact_id) DO UPDATE SET "
        "target_id=excluded.target_id, target_name=excluded.target_name, "
        "session_id=excluded.session_id, status=excluded.status, severity=excluded.severity, "
        "title=excluded.title, body=excluded.body"
    )
    bind.exec_driver_sql(
        f"""
        CREATE TRIGGER {table_name}_search_insert AFTER INSERT ON {table_name} BEGIN
            {insert};
        END
        """
    )
    bind.exec_driver_sql(
        f"""
        CREATE TRIGGER {table_name}_search_update AFTER UPDATE ON {table_name} BEGIN
            {insert};
        END
        """
    )
    bind.exec_driver_sql(
        f"""
        CREATE TRIGGER {table_name}_search_delete AFTER DELETE ON {table_name} BEGIN
            DELETE FROM search_documents
            WHERE artifact_type = '{fields["type"]}' AND artifact_id = OLD.id;
        END
        """
    )


def _backfill_documents() -> None:
    bind = op.get_bind()
    for table_name in (
        "targets",
        "evidence",
        "observations",
        "hypotheses",
        "findings",
        "sessions",
        "notes",
        "session_events",
    ):
        bind.exec_driver_sql(f"UPDATE {table_name} SET id = id")
