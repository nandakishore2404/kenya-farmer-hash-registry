"""add is_internal_service to partner

Revision ID: 0005_add_is_internal_service_to_partner
Revises: 0004_deprecate_compromised_v1_epoch
Create Date: 2026-10-28 10:00:00.000000

Addresses N4: Enables internal services (such as OAN Advisory Dispatcher / Beckn BPP)
to check farmer consent across partners without requiring direct per-farmer PartnerAssociation rows,
while preserving full partner-level isolation and 403 access control for external partners.
"""
from alembic import op
import sqlalchemy as sa

revision = '0005_add_is_internal_service_to_partner'
down_revision = '0004_deprecate_compromised_v1_epoch'
branch_labels = None
depends_on = None

def upgrade() -> None:
    with op.batch_alter_table('partner') as batch_op:
        batch_op.add_column(
            sa.Column('is_internal_service', sa.Integer(), server_default='0', nullable=False)
        )

def downgrade() -> None:
    with op.batch_alter_table('partner') as batch_op:
        batch_op.drop_column('is_internal_service')
