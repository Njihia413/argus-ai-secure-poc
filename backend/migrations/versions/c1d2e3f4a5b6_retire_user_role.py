"""retire_user_role

Remap any remaining `role='user'` rows to `customer_service` (the least-privileged
real role), drop the `default='user'` on the Users.role column, and record an
audit log entry per remapped user so the admin can review.

Revision ID: c1d2e3f4a5b6
Revises: e7f206cbd763
Create Date: 2026-04-21 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone


revision = 'c1d2e3f4a5b6'
down_revision = 'e7f206cbd763'
branch_labels = None
depends_on = None


REPLACEMENT_ROLE = 'customer_service'


def upgrade():
    bind = op.get_bind()

    affected = bind.execute(
        sa.text("SELECT id, username FROM users WHERE role = 'user'")
    ).fetchall()

    if affected:
        bind.execute(
            sa.text(
                "UPDATE users SET role = :new_role WHERE role = 'user'"
            ),
            {"new_role": REPLACEMENT_ROLE},
        )

        now = datetime.now(timezone.utc)
        for row in affected:
            bind.execute(
                sa.text(
                    """
                    INSERT INTO audit_log
                        (user_id, performed_by_user_id, action_type, status,
                         target_entity_type, target_entity_id, details, timestamp)
                    VALUES
                        (:uid, NULL, 'USER_ROLE_REMAPPED', 'SUCCESS',
                         'USER', :target_id, :details, :now)
                    """
                ),
                {
                    "uid": row[0],
                    "target_id": str(row[0]),
                    "details": (
                        f"Role 'user' retired; user '{row[1]}' (ID: {row[0]}) "
                        f"remapped to '{REPLACEMENT_ROLE}'. Admin should review "
                        f"and assign a more specific role."
                    ),
                    "now": now,
                },
            )

    with op.batch_alter_table('users') as batch_op:
        batch_op.alter_column('role', server_default=None)


def downgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.alter_column('role', server_default='user')
