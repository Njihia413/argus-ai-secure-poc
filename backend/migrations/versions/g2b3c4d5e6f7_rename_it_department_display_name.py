"""rename_it_department_to_it

Revision ID: g2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-07 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "g2b3c4d5e6f7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE users SET role = 'it' WHERE role = 'it_department'"))
    bind.execute(sa.text("UPDATE role_permissions SET role = 'it' WHERE role = 'it_department'"))
    bind.execute(sa.text("UPDATE roles SET slug = 'it', display_name = 'IT' WHERE slug = 'it_department'"))


def downgrade():
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE roles SET slug = 'it_department', display_name = 'IT Department' WHERE slug = 'it'"))
    bind.execute(sa.text("UPDATE role_permissions SET role = 'it_department' WHERE role = 'it'"))
    bind.execute(sa.text("UPDATE users SET role = 'it_department' WHERE role = 'it'"))
