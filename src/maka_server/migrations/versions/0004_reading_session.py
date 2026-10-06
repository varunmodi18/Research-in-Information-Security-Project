"""the CM-BS session each reading was sealed under (follow-up F5)

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("readings") as batch:
        batch.add_column(sa.Column("session_sid", sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("readings") as batch:
        batch.drop_column("session_sid")
