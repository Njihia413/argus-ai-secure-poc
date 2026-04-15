"""add_machine_bindings_table

Revision ID: a7b8c9d0e1f2
Revises: f622fdbbf79d
Create Date: 2025-10-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a7b8c9d0e1f2'
down_revision = 'f622fdbbf79d'
branch_labels = None
depends_on = None


def upgrade():
    # machine_bindings table was created directly; this stub records that fact.
    pass


def downgrade():
    op.drop_table('machine_bindings')
