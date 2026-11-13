"""Keep OpenCVE assessments and conditional-request cache separate from primary sources."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "opencve_records",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("modified", sa.String(40), nullable=True),
        sa.Column("normalized", sa.Text(), nullable=True),
        sa.Column("raw", sa.Text(), nullable=True),
        sa.Column("etag", sa.String(256), nullable=True),
        sa.Column("checked_at", sa.String(40), nullable=False),
        sa.Column("synced_at", sa.String(40), nullable=True),
    )


def downgrade():
    op.drop_table("opencve_records")
