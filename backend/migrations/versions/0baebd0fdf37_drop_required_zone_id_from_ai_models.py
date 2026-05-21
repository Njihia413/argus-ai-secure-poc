"""drop required_zone_id from ai_models

Revision ID: 0baebd0fdf37
Revises: ad2e1f96a5c2
Create Date: 2026-05-11 21:28:05.261592

"""
from alembic import op
import sqlalchemy as sa
# revision identifiers, used by Alembic.
revision = '0baebd0fdf37'
down_revision = 'ad2e1f96a5c2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('ai_models', schema=None) as batch_op:
        batch_op.drop_constraint('ai_models_required_zone_id_fkey', type_='foreignkey')
        batch_op.drop_column('required_zone_id')


def downgrade():
    with op.batch_alter_table('ai_models', schema=None) as batch_op:
        batch_op.add_column(sa.Column('required_zone_id', sa.INTEGER(), autoincrement=False, nullable=True))
        batch_op.create_foreign_key('ai_models_required_zone_id_fkey', 'network_zones', ['required_zone_id'], ['id'])
