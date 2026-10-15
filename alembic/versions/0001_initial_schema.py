"""initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-14 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'partner',
        sa.Column('partner_id', sa.String(length=50), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('api_key_hash', sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint('partner_id')
    )
    op.create_index(op.f('ix_partner_partner_id'), 'partner', ['partner_id'], unique=False)
    op.create_index(op.f('ix_partner_api_key_hash'), 'partner', ['api_key_hash'], unique=True)

    op.create_table(
        'farmer',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('hash_key', sa.String(length=64), nullable=False),
        sa.Column('gender', sa.String(length=5), nullable=False),
        sa.Column('age_band', sa.String(length=10), nullable=False),
        sa.Column('county_code', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("gender IN ('F', 'M', 'U')", name='chk_farmer_gender'),
        sa.CheckConstraint("age_band IN ('<18', '18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'U')", name='chk_farmer_age_band'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('hash_key')
    )
    op.create_index(op.f('ix_farmer_id'), 'farmer', ['id'], unique=False)
    op.create_index(op.f('ix_farmer_hash_key'), 'farmer', ['hash_key'], unique=True)
    op.create_index(op.f('ix_farmer_county_code'), 'farmer', ['county_code'], unique=False)

    op.create_table(
        'partner_link',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('farmer_id', sa.Integer(), nullable=False),
        sa.Column('partner_id', sa.String(length=50), nullable=False),
        sa.Column('linked_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.CheckConstraint("status IN ('active', 'removed')", name='chk_link_status'),
        sa.ForeignKeyConstraint(['farmer_id'], ['farmer.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['partner_id'], ['partner.partner_id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('farmer_id', 'partner_id', name='uq_farmer_partner')
    )
    op.create_index(op.f('ix_partner_link_farmer_id'), 'partner_link', ['farmer_id'], unique=False)
    op.create_index(op.f('ix_partner_link_partner_id'), 'partner_link', ['partner_id'], unique=False)

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('partner_id', sa.String(length=50), nullable=False),
        sa.Column('farmer_id', sa.Integer(), nullable=True),
        sa.Column('at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_id'), 'audit_log', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('audit_log')
    op.drop_table('partner_link')
    op.drop_table('farmer')
    op.drop_table('partner')
