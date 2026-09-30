from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0001_adopt_existing_workspace"
down_revision = None
branch_labels = None
depends_on = None

baseline = sa.MetaData()
sa.Table(
    "targets",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("name", sa.String(255), nullable=False, unique=True),
    sa.Column("description", sa.Text),
    sa.Column("scope", sa.Text),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "assets",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("kind", sa.String(50), nullable=False),
    sa.Column("value", sa.Text, nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "endpoints",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("method", sa.String(20), nullable=False),
    sa.Column("url", sa.Text, nullable=False),
    sa.Column("description", sa.Text),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "evidence",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("source", sa.String(255), nullable=False),
    sa.Column("kind", sa.String(50), nullable=False),
    sa.Column("content", sa.Text, nullable=False),
    sa.Column("session_id", sa.ForeignKey("sessions.id")),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "tool_executions",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("session_id", sa.ForeignKey("sessions.id")),
    sa.Column("tool_name", sa.String(100), nullable=False),
    sa.Column("arguments", sa.JSON, nullable=False),
    sa.Column("status", sa.String(30), nullable=False),
    sa.Column("approved", sa.Boolean, nullable=False),
    sa.Column("output", sa.Text),
    sa.Column("error", sa.Text),
    sa.Column("duration_ms", sa.Integer),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "auth_profiles",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("name", sa.String(100), nullable=False),
    sa.Column("auth_type", sa.String(30), nullable=False),
    sa.Column("secret_ref", sa.String(255), nullable=False, unique=True),
    sa.Column("expires_at", sa.DateTime),
    sa.Column("enabled", sa.Boolean, nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "observations",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("session_id", sa.ForeignKey("sessions.id")),
    sa.Column("summary", sa.Text, nullable=False),
    sa.Column("evidence_id", sa.ForeignKey("evidence.id")),
    sa.Column("tool_execution_id", sa.ForeignKey("tool_executions.id")),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "hypotheses",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("session_id", sa.ForeignKey("sessions.id")),
    sa.Column("statement", sa.Text, nullable=False),
    sa.Column("status", sa.String(50), nullable=False),
    sa.Column("confidence", sa.String(20), nullable=False, server_default="unknown"),
    sa.Column("evidence_id", sa.ForeignKey("evidence.id")),
    sa.Column("observation_id", sa.ForeignKey("observations.id")),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "findings",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("session_id", sa.ForeignKey("sessions.id")),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("summary", sa.Text, nullable=False),
    sa.Column("severity", sa.String(20), nullable=False),
    sa.Column("confidence", sa.String(20), nullable=False, server_default="unknown"),
    sa.Column("impact", sa.Text, nullable=False, server_default=""),
    sa.Column("reproduction", sa.Text, nullable=False, server_default=""),
    sa.Column("remediation", sa.Text, nullable=False, server_default=""),
    sa.Column("status", sa.String(20), nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
    sa.Column(
        "updated_at",
        sa.DateTime,
        nullable=False,
        server_default=sa.text("CURRENT_TIMESTAMP"),
    ),
)
sa.Table(
    "sessions",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("target_id", sa.ForeignKey("targets.id"), nullable=False),
    sa.Column("title", sa.String(255), nullable=False),
    sa.Column("status", sa.String(20), nullable=False, server_default="active"),
    sa.Column("created_at", sa.DateTime, nullable=False),
    sa.Column("updated_at", sa.DateTime, nullable=False),
)
sa.Table(
    "session_events",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("session_id", sa.ForeignKey("sessions.id"), nullable=False),
    sa.Column("event_type", sa.String(50), nullable=False),
    sa.Column("content", sa.Text, nullable=False),
    sa.Column("details", sa.JSON, nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "notes",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("session_id", sa.ForeignKey("sessions.id"), nullable=False),
    sa.Column("content", sa.Text, nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
sa.Table(
    "finding_reviews",
    baseline,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("finding_id", sa.ForeignKey("findings.id"), nullable=False),
    sa.Column("decision", sa.String(20), nullable=False),
    sa.Column("note", sa.Text, nullable=False),
    sa.Column("reviewer", sa.String(100), nullable=False),
    sa.Column("created_at", sa.DateTime, nullable=False),
)
for table_name, relationship_name in (
    ("finding_evidence", "evidence"),
    ("finding_observations", "observations"),
    ("finding_hypotheses", "hypotheses"),
    ("finding_executions", "executions"),
):
    related_table = {
        "evidence": "evidence",
        "observations": "observations",
        "hypotheses": "hypotheses",
        "executions": "tool_executions",
    }[relationship_name]
    related_column = {
        "evidence": "evidence_id",
        "observations": "observation_id",
        "hypotheses": "hypothesis_id",
        "executions": "execution_id",
    }[relationship_name]
    sa.Table(
        table_name,
        baseline,
        sa.Column("finding_id", sa.ForeignKey("findings.id"), primary_key=True),
        sa.Column(
            related_column,
            sa.ForeignKey(f"{related_table}.id"),
            primary_key=True,
        ),
    )


def upgrade() -> None:
    bind = op.get_bind()
    baseline.create_all(bind=bind)
    _add_missing_columns(
        "evidence",
        [("session_id", sa.Integer, True, None, "sessions.id")],
    )
    _add_missing_columns(
        "tool_executions",
        [("session_id", sa.Integer, True, None, "sessions.id")],
    )
    _add_missing_columns(
        "observations",
        [("session_id", sa.Integer, True, None, "sessions.id")],
    )
    _add_missing_columns(
        "hypotheses",
        [("session_id", sa.Integer, True, None, "sessions.id")],
    )
    _add_missing_columns(
        "findings",
        [
            ("session_id", sa.Integer, True, None, "sessions.id"),
            ("confidence", sa.String(20), False, "unknown", None),
            ("impact", sa.Text, False, "", None),
            ("reproduction", sa.Text, False, "", None),
            ("remediation", sa.Text, False, "", None),
            ("updated_at", sa.DateTime, False, sa.text("CURRENT_TIMESTAMP"), None),
        ],
    )
    _add_missing_columns(
        "sessions",
        [("status", sa.String(20), False, "active", None)],
    )
    _add_missing_columns(
        "observations",
        [
            ("evidence_id", sa.Integer, True, None, "evidence.id"),
            ("tool_execution_id", sa.Integer, True, None, "tool_executions.id"),
        ],
    )
    _add_missing_columns(
        "hypotheses",
        [
            ("confidence", sa.String(20), False, "unknown", None),
            ("evidence_id", sa.Integer, True, None, "evidence.id"),
            ("observation_id", sa.Integer, True, None, "observations.id"),
        ],
    )


def downgrade() -> None:
    raise NotImplementedError(
        "The initial workspace-adoption migration is intentionally irreversible."
    )


def _add_missing_columns(
    table_name: str,
    columns: list[tuple[str, Any, bool, Any, str | None]],
) -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns(table_name)}
    for name, type_, nullable, server_default, foreign_key in columns:
        if name not in existing:
            constraints = (
                [sa.ForeignKey(foreign_key, name=f"fk_{table_name}_{name}")] if foreign_key else []
            )
            with op.batch_alter_table(table_name) as batch_op:
                batch_op.add_column(
                    sa.Column(
                        name,
                        type_,
                        *constraints,
                        nullable=nullable,
                        server_default=server_default,
                    )
                )
