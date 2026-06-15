"""add zone_groups, zone_group_zones, zone_group_apps tables; drop required_zone_id from registered_apps

Revision ID: o1p2q3r4s5t6
Revises: n9i0j1k2l3m4
Create Date: 2026-06-02

"""
from alembic import op
import sqlalchemy as sa

revision = "o1p2q3r4s5t6"
down_revision = "n9i0j1k2l3m4"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create zone_groups table
    op.create_table(
        "zone_groups",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False, unique=True),
        sa.Column("description", sa.String(256), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )

    # 2. Create zone_group_zones join table
    op.create_table(
        "zone_group_zones",
        sa.Column("zone_group_id", sa.Integer(), sa.ForeignKey("zone_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("zone_id", sa.Integer(), sa.ForeignKey("network_zones.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("zone_group_id", "zone_id", name="uq_zgz_group_zone"),
    )

    # 3. Create zone_group_apps join table
    op.create_table(
        "zone_group_apps",
        sa.Column("zone_group_id", sa.Integer(), sa.ForeignKey("zone_groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("app_id", sa.Integer(), sa.ForeignKey("registered_apps.id", ondelete="CASCADE"), nullable=False),
        sa.UniqueConstraint("zone_group_id", "app_id", name="uq_zga_group_app"),
    )

    # 4. Drop required_zone_id FK and column from registered_apps
    op.execute("ALTER TABLE registered_apps DROP CONSTRAINT IF EXISTS registered_apps_required_zone_id_fkey")
    with op.batch_alter_table("registered_apps", schema=None) as batch_op:
        batch_op.drop_column("required_zone_id")


def downgrade():
    # 1. Re-add required_zone_id to registered_apps
    with op.batch_alter_table("registered_apps", schema=None) as batch_op:
        batch_op.add_column(sa.Column("required_zone_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, "network_zones", ["required_zone_id"], ["id"])

    # 2. Drop join tables and zone_groups
    op.drop_table("zone_group_apps")
    op.drop_table("zone_group_zones")
    op.drop_table("zone_groups")
