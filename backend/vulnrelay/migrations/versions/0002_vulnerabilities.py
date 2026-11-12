"""Store normalized NVD data and preserve its original source record."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("modified", sa.String(40), nullable=False),
        sa.Column("published", sa.String(40)),
        sa.Column("status", sa.String(80)),
        sa.Column("description", sa.Text()),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("severity", sa.String(32)),
        sa.Column("cvss_version", sa.String(16)),
        sa.Column("nvd_raw", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table("vulnerabilities")
