"""deprecate compromised v1 epoch

Revision ID: 0004_deprecate_compromised_v1_epoch
Revises: 0003_add_request_nonce
Create Date: 2026-10-27 12:00:00.000000

Migration Decision:
Addresses critical security defect in legacy scalar-multiplication hash_to_group.
Flags all TokenAlias records issued under key epochs 'v1' and 'ke-pilot-v1' as
'compromised_v1_legacy', marks affected FarmerEntity rows as 'quarantined_v1_epoch',
and establishes 'ke-pilot-v3' as the authoritative key epoch.
Scopes VOPRF alias updates strictly by scheme to prevent conflation with legacy-HMAC.
Quarantines partner_association rows for quarantined entities to preserve telemetry reconciliation.
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

    # 2. Namespace legacy HMAC keys to prevent conflation with VOPRF epochs
    op.execute(
        "UPDATE token_alias SET key_id = 'legacy-hmac-v1' WHERE scheme = 'legacy_hmac' AND key_id = 'v1'"
    )
    
    # 3. Flag compromised VOPRF aliases as non-authoritative (scoped strictly to VOPRF schemes)
    op.execute(
        """
        UPDATE token_alias 
        SET status = 'compromised_v1_legacy' 
        WHERE scheme IN ('voprf_ristretto255', 'voprf_secp256k1') 
          AND key_id IN ('v1', 'ke-pilot-v1', 'ke-pilot-v2')
        """
    )
    
    # 4. Quarantine entities tied exclusively to compromised VOPRF aliases
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

    # 5. Quarantine partner associations for quarantined entities to preserve telemetry fidelity
    op.execute(
        """
        UPDATE partner_association
        SET status = 'quarantined_v1_epoch'
        WHERE entity_id IN (
            SELECT entity_id FROM farmer_entity WHERE status = 'quarantined_v1_epoch'
        )
        """
    )

def downgrade() -> None:
    """
    WARNING: FORWARD-ONLY MIGRATION NOTICE
    downgrade() is provided for schema rollback symmetry in fresh or staging environments,
    but is UNSAFE once new production data has been written post-upgrade.
    Specifically:
      - It resets all 'quarantined_v1_epoch' rows to 'active' without distinguishing entities
        or associations that may have been quarantined later for other operational reasons.
      - It re-conflates 'legacy-hmac-v1' back to the generic 'v1' key_id namespace.
    Do NOT execute this downgrade against a live production database with post-upgrade transactions.
    """
    op.execute(
        "UPDATE partner_association SET status = 'active' WHERE status = 'quarantined_v1_epoch'"
    )
    op.execute(
        "UPDATE farmer_entity SET status = 'active' WHERE status = 'quarantined_v1_epoch'"
    )
    op.execute(
        "UPDATE token_alias SET key_id = 'v1' WHERE scheme = 'legacy_hmac' AND key_id = 'legacy-hmac-v1'"
    )
    op.drop_column('token_alias', 'status')
