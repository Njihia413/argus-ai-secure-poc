"""Add product_id and vendor_id to SecurityKey

Revision ID: 9bb9f08216c2
Revises: 8639fffff42a
Create Date: 2025-05-28 13:01:58.319928

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9bb9f08216c2'
down_revision = '8639fffff42a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.add_column(sa.Column('product_id', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('vendor_id', sa.String(length=100), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('security_key', schema=None) as batch_op:
        batch_op.drop_column('vendor_id')
        batch_op.drop_column('product_id')

    # ### end Alembic commands ###
