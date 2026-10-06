"""a CM's designated CH and its undelivered readings (follow-up D2)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("designated", sa.String(length=20), nullable=True))
        batch.add_column(sa.Column("undelivered", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("undelivered")
        batch.drop_column("designated")
