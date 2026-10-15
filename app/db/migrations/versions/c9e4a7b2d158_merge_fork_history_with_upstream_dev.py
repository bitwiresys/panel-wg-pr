"""merge fork history with upstream dev

Production was migrated along the fork's v5.4.1 line (head 97c5e4650b63).
Upstream dev's later migrations (a8c2d491e705 and its ancestors) were never
applied there. This merge lets alembic run them on top of 97c5e4650b63.

Do not delete 35b0826f89b6, 97c5e4650b63 or b721efe0ddd0 when syncing upstream:
deployed databases are stamped with them.

Revision ID: c9e4a7b2d158
Revises: 97c5e4650b63, a8c2d491e705
Create Date: 2026-10-15 00:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = "c9e4a7b2d158"
down_revision = ("97c5e4650b63", "a8c2d491e705")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
