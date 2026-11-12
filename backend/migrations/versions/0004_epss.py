"""Store FIRST EPSS measurements independently of other sources."""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("measured_on", sa.String(10), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table("epss_scores")
