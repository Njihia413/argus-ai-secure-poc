"""add_vaults_table

Revision ID: m8h9i0j1k2l3
Revises: l7g8h9i0j1k2
Create Date: 2026-05-21 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "m8h9i0j1k2l3"
down_revision = ("l7g8h9i0j1k2", "aa5a2d6a0b11")
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    bind.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS vaults (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            owner_user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ,
            is_deleted BOOLEAN NOT NULL DEFAULT FALSE
        )
    """))
    bind.execute(sa.text("""
        ALTER TABLE encrypted_files
        ADD COLUMN IF NOT EXISTS vault_id INTEGER REFERENCES vaults(id)
    """))


def downgrade():
    bind = op.get_bind()
    bind.execute(sa.text("ALTER TABLE encrypted_files DROP COLUMN IF EXISTS vault_id"))
    bind.execute(sa.text("DROP TABLE IF EXISTS vaults"))
