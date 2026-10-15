"""add received_at and partner active

Revision ID: 0002_add_received_at_and_active
Revises: 0001_initial_schema
Create Date: 2026-10-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '0002_add_received_at_and_active'
down_revision = '0001_initial_schema'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Add received_at to partner_link
    with op.batch_alter_table('partner_link') as batch_op:
        batch_op.add_column(sa.Column('received_at', sa.DateTime(), server_default=sa.func.now(), nullable=False))
        batch_op.create_index('ix_partner_link_received_at', ['received_at'], unique=False)
        
    # Add active to partner
    with op.batch_alter_table('partner') as batch_op:
        batch_op.add_column(sa.Column('active', sa.Integer(), server_default='1', nullable=False))

def downgrade() -> None:
    with op.batch_alter_table('partner') as batch_op:
        batch_op.drop_column('active')
        
    with op.batch_alter_table('partner_link') as batch_op:
        batch_op.drop_index('ix_partner_link_received_at')
        batch_op.drop_column('received_at')
