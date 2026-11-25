"""Opt-in AI settings, daily request quota, and bounded summary cache."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ai_settings",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("document", sa.Text(), nullable=False),
    )
    op.create_table(
        "ai_usage",
        sa.Column("day", sa.String(10), primary_key=True),
        sa.Column("requests", sa.Integer(), nullable=False),
    )
    op.create_table(
        "ai_cache",
        sa.Column("cache_key", sa.String(64), primary_key=True),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )


def downgrade():
    for name in ("ai_cache", "ai_usage", "ai_settings"):
        op.drop_table(name)
