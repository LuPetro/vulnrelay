"""Keep CISA KEV records separately from NVD assessments."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kev_entries",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("date_added", sa.String(20), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table("kev_entries")
