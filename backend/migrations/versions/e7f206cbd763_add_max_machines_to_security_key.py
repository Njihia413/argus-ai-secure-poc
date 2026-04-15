"""add max_machines to security_key

Revision ID: e7f206cbd763
Revises: e5f2f41872b8
Create Date: 2026-04-01 13:17:47.417290

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e7f206cbd763'
down_revision = 'e5f2f41872b8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'max_machines',
            sa.Integer(),
            nullable=False,
            server_default=sa.text('1'),
        ))


def downgrade():
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.drop_column('max_machines')
