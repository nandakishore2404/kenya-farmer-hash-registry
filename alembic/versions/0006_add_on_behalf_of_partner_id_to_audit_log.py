"""add on_behalf_of_partner_id to audit_log

Revision ID: 0006_add_on_behalf_of_partner_id_to_audit_log
Revises: 0005_add_is_internal_service_to_partner
Create Date: 2026-10-28 10:30:00.000000

Addresses N8: Records the governing target delivery partner when an internal
service (e.g. OAN Advisory Dispatcher / Beckn BPP) performs a PEP consent check.
"""
from alembic import op
import sqlalchemy as sa

revision = '0006_add_on_behalf_of_partner_id_to_audit_log'
down_revision = '0005_add_is_internal_service_to_partner'
branch_labels = None
depends_on = None

def upgrade() -> None:
    with op.batch_alter_table('audit_log') as batch_op:
        batch_op.add_column(
            sa.Column('on_behalf_of_partner_id', sa.String(length=50), nullable=True)
        )

def downgrade() -> None:
    with op.batch_alter_table('audit_log') as batch_op:
        batch_op.drop_column('on_behalf_of_partner_id')
