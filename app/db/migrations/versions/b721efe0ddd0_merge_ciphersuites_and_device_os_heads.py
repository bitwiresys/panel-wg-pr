"""merge cipherSuites and device_os heads

Revision ID: b721efe0ddd0
Revises: 6a9fff8290b9, e8a1f2c3d4b5
Create Date: 2026-08-21 01:09:20.540811

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b721efe0ddd0'
down_revision = ('6a9fff8290b9', 'e8a1f2c3d4b5')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
