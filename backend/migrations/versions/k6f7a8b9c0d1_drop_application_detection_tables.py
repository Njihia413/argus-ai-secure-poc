"""drop_application_detection_tables

Revision ID: k6f7a8b9c0d1
Revises: g2b3c4d5e6f7
Create Date: 2026-05-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "k6f7a8b9c0d1"
down_revision = "g2b3c4d5e6f7"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    # Clean role_permissions rows that referenced app, app_feature, or the applications admin section.
    bind.execute(sa.text(
        "DELETE FROM role_permissions WHERE resource_type IN ('app', 'app_feature')"
    ))
    bind.execute(sa.text(
        "DELETE FROM role_permissions WHERE resource_type = 'admin_section' AND resource_id = 'applications'"
    ))
    # Drop tables with IF EXISTS to handle any DB state (some may already be gone).
    bind.execute(sa.text("DROP TABLE IF EXISTS machine_raw_inventory"))
    bind.execute(sa.text("DROP TABLE IF EXISTS application_features"))
    bind.execute(sa.text("DROP TABLE IF EXISTS machine_installed_apps"))
    bind.execute(sa.text("DROP TABLE IF EXISTS application_catalog"))
    bind.execute(sa.text("DROP TABLE IF EXISTS applications"))


def downgrade():
    pass
