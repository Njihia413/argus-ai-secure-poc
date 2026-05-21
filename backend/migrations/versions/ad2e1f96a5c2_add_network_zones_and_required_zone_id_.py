"""add network zones and required_zone_id to models and apps

Revision ID: ad2e1f96a5c2
Revises: l7g8h9i0j1k2
Create Date: 2026-05-11 21:23:09.828415

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ad2e1f96a5c2'
down_revision = 'l7g8h9i0j1k2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('ai_models', schema=None) as batch_op:
        batch_op.add_column(sa.Column('required_zone_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, 'network_zones', ['required_zone_id'], ['id'])

    with op.batch_alter_table('registered_apps', schema=None) as batch_op:
        batch_op.add_column(sa.Column('required_zone_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, 'network_zones', ['required_zone_id'], ['id'])


def downgrade():
    with op.batch_alter_table('registered_apps', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('required_zone_id')

    with op.batch_alter_table('ai_models', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('required_zone_id')
