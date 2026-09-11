"""merge upstream sync heads

Revision ID: 35b0826f89b6
Revises: 7c4bd5128e62, b721efe0ddd0
Create Date: 2026-09-11 10:37:49.223223

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '35b0826f89b6'
down_revision = ('7c4bd5128e62', 'b721efe0ddd0')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
