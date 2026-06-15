"""add_minio_storage_fields

Revision ID: q3r4s5t6u7v8
Revises: p2q3r4s5t6u7
Create Date: 2026-06-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "q3r4s5t6u7v8"
down_revision = "p2q3r4s5t6u7"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "encrypted_files",
        sa.Column(
            "storage_backend",
            sa.String(20),
            nullable=False,
            server_default="local",
        ),
    )
    op.add_column(
        "encrypted_files",
        sa.Column("storage_key", sa.String(255), nullable=True),
    )
    op.alter_column("encrypted_files", "encrypted_path", nullable=True)


def downgrade():
    op.alter_column("encrypted_files", "encrypted_path", nullable=False)
    op.drop_column("encrypted_files", "storage_key")
    op.drop_column("encrypted_files", "storage_backend")
