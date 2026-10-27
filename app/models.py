import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    CheckConstraint,
    UniqueConstraint,
    Text,
    Index
)
from sqlalchemy.orm import relationship
from app.database import Base

VALID_GENDERS = ('F', 'M', 'U')
VALID_AGE_BANDS = ('<18', '18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'U')
VALID_LINK_STATUSES = ('active', 'removed')
VALID_CONSENT_STATUSES = ('PENDING', 'ACTIVE', 'WITHDRAWN', 'EXPIRED')

def utcnow():
    return datetime.now(timezone.utc)

def generate_uuid():
    return str(uuid.uuid4())

# ============================================================================
# TARGET ARCHITECTURE: CANONICAL FARMER ENTITY & MULTI-KEY ALIASING
# ============================================================================

class FarmerEntity(Base):
    """
    Core pseudonymous farmer identity entity (UUID).
    Stable regardless of VOPRF key rotation or consent mutations.
    """
    __tablename__ = "farmer_entity"

    entity_id = Column(String(36), primary_key=True, default=generate_uuid)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False)

    # Relationships
    aliases = relationship("TokenAlias", back_populates="entity", cascade="all, delete-orphan")
    associations = relationship("PartnerAssociation", back_populates="entity", cascade="all, delete-orphan")
    consents = relationship("FarmerConsent", back_populates="entity", cascade="all, delete-orphan")


class TokenAlias(Base):
    """
    Maps cryptographic digests D to an entity.
    Supports multi-key migration: VOPRF v1, Legacy HMAC, and future National Farmer ID.
    D = HMAC-SHA256(SERVER_KEY, LP("oan-registry-v1") || LP(pilot_id) || LP(key_id) || T)
    """
    __tablename__ = "token_alias"

    alias_id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="CASCADE"), nullable=False, index=True)
    pilot_id = Column(String(50), nullable=False, default="kenya-pilot")
    scheme = Column(String(50), nullable=False)  # 'voprf_ristretto255', 'legacy_hmac', 'kenya_kfr'
    key_id = Column(String(50), nullable=False)  # e.g. 'v1'
    digest_d = Column(String(64), nullable=False, unique=True, index=True)
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
    partner_id = Column(String(50), ForeignKey("partner.partner_id"), nullable=False, index=True)
    role = Column(String(30), default="contributor", nullable=False)  # 'onboarder', 'primary', 'contributor'
    first_seen = Column(DateTime, default=utcnow, nullable=False)
    last_seen = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    status = Column(String(20), default="active", nullable=False)

    __table_args__ = (
        UniqueConstraint("entity_id", "partner_id", name="uq_entity_partner_assoc"),
    )

    entity = relationship("FarmerEntity", back_populates="associations")
    partner = relationship("Partner")


class FarmerConsent(Base):
    """
    First-Class Consent State Model.
    Protects downstream advisory/messaging engines through Policy Enforcement Points.
    """
    __tablename__ = "farmer_consent"

    consent_id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="CASCADE"), nullable=False, index=True)
    partner_id = Column(String(50), ForeignKey("partner.partner_id"), nullable=False, index=True)
    purpose = Column(String(50), nullable=False, index=True)  # 'ADVISORY', 'FERTILIZER_SUBSIDY', 'PEST_ALERT'
    status = Column(String(20), default="ACTIVE", nullable=False, index=True)  # 'PENDING', 'ACTIVE', 'WITHDRAWN', 'EXPIRED'
    version = Column(String(20), nullable=False, default="v1.0")
    channel = Column(String(30), nullable=False, default="WHITE_LABEL_APP")  # 'WHITE_LABEL_APP', 'USSD', 'PARTNER_API'
    evidence_ref = Column(Text, nullable=True)
    captured_at = Column(DateTime, default=utcnow, nullable=False)
    withdrawn_at = Column(DateTime, nullable=True)
    withdrawal_reason = Column(String(100), nullable=True)

    __table_args__ = (
        CheckConstraint(f"status IN {VALID_CONSENT_STATUSES}", name="chk_consent_status"),
    )

    entity = relationship("FarmerEntity", back_populates="consents")
    partner = relationship("Partner")


# ============================================================================
# LEGACY PILOT MODELS (Preserved for 100% Backward Compatibility)
# ============================================================================

class Farmer(Base):
    __tablename__ = "farmer"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    hash_key = Column(String(64), unique=True, nullable=False, index=True)
    gender = Column(String(5), nullable=False)
    age_band = Column(String(10), nullable=False)
    county_code = Column(String(10), nullable=False, index=True)
    entity_id = Column(String(36), ForeignKey("farmer_entity.entity_id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        CheckConstraint(f"gender IN {VALID_GENDERS}", name="chk_farmer_gender"),
        CheckConstraint(f"age_band IN {VALID_AGE_BANDS}", name="chk_farmer_age_band"),
    )

    partner_links = relationship("PartnerLink", back_populates="farmer", cascade="all, delete-orphan")


class PartnerLink(Base):
    __tablename__ = "partner_link"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    farmer_id = Column(Integer, ForeignKey("farmer.id", ondelete="CASCADE"), nullable=False, index=True)
    partner_id = Column(String(50), ForeignKey("partner.partner_id"), nullable=False, index=True)
    linked_at = Column(DateTime, default=utcnow, nullable=False)
    received_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    status = Column(String(20), default="active", nullable=False)

    __table_args__ = (
        UniqueConstraint("farmer_id", "partner_id", name="uq_farmer_partner"),
        CheckConstraint(f"status IN {VALID_LINK_STATUSES}", name="chk_link_status"),
    )

    farmer = relationship("Farmer", back_populates="partner_links")
    partner = relationship("Partner")


class Partner(Base):
    __tablename__ = "partner"

    partner_id = Column(String(50), primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    api_key_hash = Column(String(64), nullable=False, unique=True, index=True)
    active = Column(Integer, default=1, nullable=False)  # 1 for active, 0 for disabled


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action = Column(String(50), nullable=False)
    partner_id = Column(String(50), nullable=False)
    farmer_id = Column(Integer, nullable=True)  # Strictly farmer_id or NULL; NEVER store incoming hash or phone!
    entity_id = Column(String(36), nullable=True)
    at = Column(DateTime, default=utcnow, nullable=False)


class RequestNonce(Base):
    __tablename__ = "request_nonce"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    partner_id = Column(String(50), ForeignKey("partner.partner_id"), nullable=False, index=True)
    nonce = Column(String(100), nullable=False)
    seen_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("partner_id", "nonce", name="uq_partner_nonce"),
    )
