"""add request_nonce table

Revision ID: 0003_add_request_nonce
Revises: 0002_add_received_at_and_active
Create Date: 2026-10-15 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '0003_add_request_nonce'
down_revision = '0002_add_received_at_and_active'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'request_nonce',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('partner_id', sa.String(length=50), nullable=False),
        sa.Column('nonce', sa.String(length=100), nullable=False),
        sa.Column('seen_at', sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['partner_id'], ['partner.partner_id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('partner_id', 'nonce', name='uq_partner_nonce')
    )
    op.create_index(op.f('ix_request_nonce_id'), 'request_nonce', ['id'], unique=False)
    op.create_index(op.f('ix_request_nonce_partner_id'), 'request_nonce', ['partner_id'], unique=False)
    op.create_index(op.f('ix_request_nonce_seen_at'), 'request_nonce', ['seen_at'], unique=False)

def downgrade() -> None:
    op.drop_table('request_nonce')
