"""deprecate compromised v1 epoch

Revision ID: 0004_deprecate_compromised_v1_epoch
Revises: 0003_add_request_nonce
Create Date: 2026-10-27 12:00:00.000000

Migration Decision:
Addresses critical security defect in legacy scalar-multiplication hash_to_group.
Flags all TokenAlias records issued under key epochs 'v1' and 'ke-pilot-v1' as
'compromised_v1_legacy', marks affected FarmerEntity rows as 'quarantined_v1_epoch',
and establishes 'ke-pilot-v2' as the authoritative key epoch.
"""
from alembic import op
import sqlalchemy as sa

revision = '0004_deprecate_compromised_v1_epoch'
down_revision = '0003_add_request_nonce'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. Add status column to token_alias
    op.add_column(
        'token_alias',
        sa.Column('status', sa.String(length=30), nullable=False, server_default='active')
    )
    
    # 2. Flag compromised legacy aliases as non-authoritative
    op.execute(
        "UPDATE token_alias SET status = 'compromised_v1_legacy' WHERE key_id IN ('v1', 'ke-pilot-v1')"
    )
    
    # 3. Quarantine entities tied exclusively to compromised v1 aliases
    op.execute(
        """
        UPDATE farmer_entity 
        SET status = 'quarantined_v1_epoch' 
        WHERE entity_id IN (
            SELECT entity_id FROM token_alias WHERE status = 'compromised_v1_legacy'
        )
        AND entity_id NOT IN (
            SELECT entity_id FROM token_alias WHERE status = 'active'
        )
        """
    )

def downgrade() -> None:
    op.execute(
        "UPDATE farmer_entity SET status = 'active' WHERE status = 'quarantined_v1_epoch'"
    )
    op.drop_column('token_alias', 'status')
