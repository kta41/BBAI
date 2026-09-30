from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_session_labels_auth_roles"
down_revision = "0002_fts_search"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sessions",
        sa.Column("labels", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "auth_profiles",
        sa.Column("role", sa.String(30), nullable=False, server_default="custom"),
    )


def downgrade() -> None:
    with op.batch_alter_table("auth_profiles") as batch_op:
        batch_op.drop_column("role")
    op.drop_column("sessions", "labels")
