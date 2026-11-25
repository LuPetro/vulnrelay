"""Persist security news and independent feed health."""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "news_items",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("url", sa.String(1200), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("published", sa.String(40)),
        sa.Column("discovered", sa.Float(), nullable=False),
    )
    op.create_index("ix_news_items_discovered", "news_items", ["discovered"])
    op.create_table(
        "news_feed_state",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("last_success", sa.Float()),
        sa.Column("last_attempt", sa.Float(), nullable=False),
        sa.Column("last_error", sa.String(100)),
    )


def downgrade():
    op.drop_table("news_feed_state")
    op.drop_index("ix_news_items_discovered", table_name="news_items")
    op.drop_table("news_items")
