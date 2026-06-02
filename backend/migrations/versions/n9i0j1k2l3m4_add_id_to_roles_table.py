"""add id column to roles table, change primary key from slug to id

Revision ID: n9i0j1k2l3m4
Revises: m8h9i0j1k2l3
Create Date: 2026-06-02

"""
from alembic import op
import sqlalchemy as sa

revision = "n9i0j1k2l3m4"
down_revision = "m8h9i0j1k2l3"
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add id column (nullable initially so existing rows can be backfilled)
    op.add_column("roles", sa.Column("id", sa.Integer(), nullable=True))

    # 2. Create a sequence for the new id column and backfill existing rows
    op.execute("CREATE SEQUENCE IF NOT EXISTS roles_id_seq START 1")
    op.execute("UPDATE roles SET id = nextval('roles_id_seq')")

    # 3. Set the column to NOT NULL now that all rows have a value
    op.alter_column("roles", "id", nullable=False)

    # 4. Set the sequence as the default for future inserts
    op.execute("ALTER TABLE roles ALTER COLUMN id SET DEFAULT nextval('roles_id_seq')")

    # 5. Drop the old primary key constraint (slug was the PK)
    op.drop_constraint("roles_pkey", "roles", type_="primary")

    # 6. Add the new integer primary key
    op.create_primary_key("roles_pkey", "roles", ["id"])

    # 7. Ensure slug remains unique and indexed
    op.create_unique_constraint("uq_roles_slug", "roles", ["slug"])

    # 8. Tie the sequence ownership to the column so it's dropped with it
    op.execute("ALTER SEQUENCE roles_id_seq OWNED BY roles.id")


def downgrade():
    op.drop_constraint("uq_roles_slug", "roles", type_="unique")
    op.drop_constraint("roles_pkey", "roles", type_="primary")
    op.create_primary_key("roles_pkey", "roles", ["slug"])
    op.drop_column("roles", "id")
    op.execute("DROP SEQUENCE IF EXISTS roles_id_seq")
