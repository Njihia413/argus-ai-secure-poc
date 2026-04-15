"""add require_machine_binding to security_key

Revision ID: e5f2f41872b8
Revises: a7b8c9d0e1f2
Create Date: 2026-04-01 12:29:03.345713

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5f2f41872b8'
down_revision = 'a7b8c9d0e1f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'require_machine_binding',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('false'),
        ))


def downgrade():
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.drop_column('require_machine_binding')
