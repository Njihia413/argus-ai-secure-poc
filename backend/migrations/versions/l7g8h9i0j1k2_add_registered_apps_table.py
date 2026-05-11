"""add_registered_apps_table

Revision ID: l7g8h9i0j1k2
Revises: k6f7a8b9c0d1
Create Date: 2026-05-11 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "l7g8h9i0j1k2"
down_revision = "k6f7a8b9c0d1"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    bind.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS registered_apps (
            id SERIAL PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            slug VARCHAR(64) NOT NULL UNIQUE,
            description VARCHAR(256),
            api_key_hash VARCHAR(128) NOT NULL,
            api_key_prefix VARCHAR(16) NOT NULL,
            callback_url VARCHAR(256),
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            created_by VARCHAR(100)
        )
    """))


def downgrade():
    op.drop_table("registered_apps")
