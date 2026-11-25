"""Persist OSV package findings and per-asset query health."""

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "osv_findings",
        sa.Column("asset_id", sa.String(36), primary_key=True),
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("osv_id", sa.String(200), primary_key=True),
        sa.Column("ecosystem", sa.String(100), nullable=False),
        sa.Column("package", sa.String(200), nullable=False),
        sa.Column("version", sa.String(100), nullable=False),
        sa.Column("record", sa.Text(), nullable=False),
        sa.Column("checked_at", sa.Float(), nullable=False),
    )
    op.create_index("ix_osv_findings_cve", "osv_findings", ["cve_id"])
    op.create_table(
        "osv_asset_state",
        sa.Column("asset_id", sa.String(36), primary_key=True),
        sa.Column("last_attempt", sa.Float(), nullable=False),
        sa.Column("last_success", sa.Float()),
        sa.Column("last_error", sa.String(200)),
    )


def downgrade():
    op.drop_table("osv_asset_state")
    op.drop_index("ix_osv_findings_cve", table_name="osv_findings")
    op.drop_table("osv_findings")
