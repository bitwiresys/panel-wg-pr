"""add device_os to hosts

Revision ID: e8a1f2c3d4b5
Revises: a8c2d491e705
Create Date: 2026-08-19 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "e8a1f2c3d4b5"
down_revision = "a8c2d491e705"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("device_os", sa.String(length=100), nullable=True, server_default=""))


def downgrade() -> None:
    op.drop_column("hosts", "device_os")
