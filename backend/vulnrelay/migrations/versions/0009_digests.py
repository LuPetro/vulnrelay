"""Persist scheduled report configuration and next occurrence."""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "digests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("document", sa.Text(), nullable=False),
        sa.Column("next_run", sa.Float(), nullable=False),
    )


def downgrade():
    op.drop_table("digests")
