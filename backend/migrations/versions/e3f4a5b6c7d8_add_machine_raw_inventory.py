"""add_machine_raw_inventory

Unfiltered per-machine app inventory. Decoupled from the curated
`applications` catalog so admins see every app on a bound workstation
without having to pre-seed each bundle ID.

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-04-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'e3f4a5b6c7d8'
down_revision = 'd2e3f4a5b6c7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'machine_raw_inventory',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('machine_binding_id', sa.Integer(), nullable=False),
        sa.Column('bundle_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('path', sa.Text(), nullable=True),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['machine_binding_id'], ['machine_bindings.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_raw_inventory_binding',
        'machine_raw_inventory',
        ['machine_binding_id'],
    )


def downgrade():
    op.drop_index('ix_raw_inventory_binding', table_name='machine_raw_inventory')
    op.drop_table('machine_raw_inventory')
