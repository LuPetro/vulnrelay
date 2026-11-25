"""Persistent asset configuration, rules, connectors and delivery outbox."""

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    for name in ("assets", "rules", "connectors"):
        op.create_table(
            name,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("document", sa.Text(), nullable=False),
        )
    op.create_table(
        "outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_key", sa.String(64), unique=True, nullable=False),
        sa.Column("connector_id", sa.String(36), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.Float(), nullable=False),
        sa.Column("lease_until", sa.Float(), nullable=True),
        sa.Column("lease_token", sa.String(36), nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("sent_at", sa.Float(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
    )
    op.create_index("ix_outbox_pending", "outbox", ["state", "available_at"])
    op.create_table(
        "connector_limits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("available_at", sa.Float(), nullable=False),
    )
    op.create_table(
        "engine_state",
        sa.Column("name", sa.String(80), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
    )


def downgrade():
    for name in ("engine_state", "connector_limits", "outbox", "connectors", "rules", "assets"):
        op.drop_table(name)
