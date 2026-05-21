"""drop callback_url from registered_apps

Revision ID: aa5a2d6a0b11
Revises: 0baebd0fdf37
Create Date: 2026-05-11 21:59:31.962476

"""
from alembic import op
import sqlalchemy as sa
# revision identifiers, used by Alembic.
revision = 'aa5a2d6a0b11'
down_revision = '0baebd0fdf37'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('registered_apps', schema=None) as batch_op:
        batch_op.drop_column('callback_url')


def downgrade():
    with op.batch_alter_table('registered_apps', schema=None) as batch_op:
        batch_op.add_column(sa.Column('callback_url', sa.VARCHAR(length=256), autoincrement=False, nullable=True))
