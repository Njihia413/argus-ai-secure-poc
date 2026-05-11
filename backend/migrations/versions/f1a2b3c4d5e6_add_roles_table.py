"""add_roles_table

Revision ID: f1a2b3c4d5e6
Revises: e3f4a5b6c7d8
Create Date: 2026-05-07 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "f1a2b3c4d5e6"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "roles",
        sa.Column("slug", sa.String(32), primary_key=True),
        sa.Column("display_name", sa.String(64), nullable=False),
        sa.Column("is_system", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.get_bind().execute(
        sa.text(
            """
            INSERT INTO roles (slug, display_name, is_system) VALUES
              ('admin',            'Admin',            TRUE),
              ('hr',               'HR',               TRUE),
              ('manager',          'Manager',          TRUE),
              ('it',               'IT',               TRUE),
              ('customer_service', 'Customer Service', TRUE)
            """
        )
    )


def downgrade():
    op.drop_table("roles")
