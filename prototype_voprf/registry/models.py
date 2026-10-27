"""
Database Models for OAN Kenya Temporary Farmer Registry & Consent Platform
Uses SQLite / PostgreSQL compatible SQLAlchemy models.
Separates:
  1. Farmer Identity (Stable entity)
  2. Token Aliases (Multi-key deduplication mapping)
  3. Partner Associations (Attribution & multi-provider links)
  4. Consent Records (First-class mutable lifecycle with downstream audit)
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    DateTime,
    ForeignKey,
    CheckConstraint,
    UniqueConstraint,
    Text,
    Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def utcnow():
    return datetime.now(timezone.utc)

def generate_uuid():
    return str(uuid.uuid4())

class FarmerEntity(Base):
    """
    Core pseudonymous farmer entity. Stable regardless of key rotation or consent state.
    """
    __tablename__ = "farmer_entity"

    entity_id = Column(String(36), primary_key=True, default=generate_uuid)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False) # 'active', 'deactivated'

    # Relationships
    aliases = relationship("TokenAlias", back_populates="entity", cascade="all, delete-orphan")
    associations = relationship("PartnerAssociation", back_populates="entity", cascade="all, delete-orphan")
    consents = relationship("FarmerConsent", back_populates="entity", cascade="all, delete-orphan")

class TokenAlias(Base):
    """
    Maps cryptographic digests D to an entity.
    Supports multi-key migration: VOPRF v1, Legacy HMAC, and future National Farmer ID.
    D = HMAC-SHA256(registry_storage_key, LP("oan-registry-v1") || LP(pilot_id) || LP(key_id) || T)
    """
    __tablename__ = "token_alias"

    alias_id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="CASCADE"), nullable=False, index=True)
    pilot_id = Column(String(50), nullable=False, default="kenya-pilot")
    scheme = Column(String(50), nullable=False) # 'voprf_ristretto255', 'legacy_hmac', 'kenya_kfr'
    key_id = Column(String(50), nullable=False) # e.g. 'ke-pilot-v2'
    digest_d = Column(String(64), nullable=False, unique=True, index=True)
    status = Column(String(30), default="active", nullable=False) # 'active', 'compromised_v1_legacy'
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("pilot_id", "key_id", "digest_d", name="uq_pilot_key_digest"),
    )

    entity = relationship("FarmerEntity", back_populates="aliases")

class PartnerAssociation(Base):
    """
    Multi-provider association tracking.
    Decouples Identity from Attribution.
    """
    __tablename__ = "partner_association"

    association_id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="CASCADE"), nullable=False, index=True)
    partner_id = Column(String(50), nullable=False, index=True)
    role = Column(String(30), default="contributor", nullable=False) # 'onboarder', 'primary', 'contributor'
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False) # 'active', 'removed'

    __table_args__ = (
        UniqueConstraint("entity_id", "partner_id", name="uq_entity_partner"),
    )

    entity = relationship("FarmerEntity", back_populates="associations")

class FarmerConsent(Base):
    """
    First-Class Consent State Model.
    Protects downstream advisory/messaging engines.
    """
    __tablename__ = "farmer_consent"

    consent_id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="CASCADE"), nullable=False, index=True)
    partner_id = Column(String(50), nullable=False, index=True)
    purpose = Column(String(50), nullable=False, index=True) # 'ADVISORY', 'FERTILIZER_SUBSIDY', 'PEST_ALERT'
    status = Column(String(20), default="ACTIVE", nullable=False, index=True) # 'PENDING', 'ACTIVE', 'WITHDRAWN', 'EXPIRED'
    version = Column(String(20), nullable=False, default="v1.0")
    channel = Column(String(30), nullable=False, default="WHITE_LABEL_APP") # 'WHITE_LABEL_APP', 'USSD', 'PARTNER_API'
    evidence_ref = Column(Text, nullable=True) # e.g. digital signature or paper form UUID
    captured_at = Column(DateTime, default=utcnow, nullable=False)
    withdrawn_at = Column(DateTime, nullable=True)
    withdrawal_reason = Column(String(100), nullable=True)

    __table_args__ = (
        CheckConstraint("status IN ('PENDING', 'ACTIVE', 'WITHDRAWN', 'EXPIRED')", name="chk_consent_status"),
    )

    entity = relationship("FarmerEntity", back_populates="consents")

class AuditLog(Base):
    """
    Immutable audit trail for all identity, consent, and attribution events.
    """
    __tablename__ = "audit_log"

    event_id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(String(36), nullable=True, index=True)
    partner_id = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    details = Column(Text, nullable=True)
