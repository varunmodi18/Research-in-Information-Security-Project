"""lab run tags on frames and security events (IMPLEMENTATION_PLAN.md M6-T1)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("frames", "security_events"):
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("run_tag", sa.String(length=64), nullable=True))
            batch.create_index(f"ix_{table}_run_tag", ["run_tag"])


def downgrade() -> None:
    for table in ("frames", "security_events"):
        with op.batch_alter_table(table) as batch:
            batch.drop_index(f"ix_{table}_run_tag")
            batch.drop_column("run_tag")
