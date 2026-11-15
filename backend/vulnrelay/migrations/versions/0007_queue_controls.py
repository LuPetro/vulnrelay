"""Separate provider cooldowns from delivery failures and preserve queue dismissals."""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("outbox", sa.Column("failures", sa.Integer(), nullable=False, server_default="0"))
    op.execute("""UPDATE outbox SET failures=attempts
        WHERE state IN ('retry','sending','failed')
        AND COALESCE(last_error,'') != 'Telegram rate limit'""")
    op.add_column(
        "connector_limits",
        sa.Column("rate_limited_until", sa.Float(), nullable=False, server_default="0"),
    )

    op.execute("""UPDATE connector_limits SET rate_limited_until=available_at
        WHERE EXISTS (SELECT 1 FROM outbox o WHERE o.connector_id=connector_limits.id
        AND o.last_error='Telegram rate limit' AND o.state IN ('retry','failed'))""")


def downgrade():
    with op.batch_alter_table("connector_limits") as batch:
        batch.drop_column("rate_limited_until")
    with op.batch_alter_table("outbox") as batch:
        batch.drop_column("failures")
