"""rename zone_groups tables to network_zone_groups

Revision ID: p2q3r4s5t6u7
Revises: o1p2q3r4s5t6
Create Date: 2026-06-02

"""
from alembic import op

revision = "p2q3r4s5t6u7"
down_revision = "o1p2q3r4s5t6"
branch_labels = None
depends_on = None


def upgrade():
    op.rename_table("zone_group_apps", "network_zone_group_apps")
    op.rename_table("zone_group_zones", "network_zone_group_zones")
    op.rename_table("zone_groups", "network_zone_groups")


def downgrade():
    op.rename_table("network_zone_groups", "zone_groups")
    op.rename_table("network_zone_group_zones", "zone_group_zones")
    op.rename_table("network_zone_group_apps", "zone_group_apps")
