from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    CheckConstraint,
    UniqueConstraint,
    Index
)
from sqlalchemy.orm import relationship
from app.database import Base

VALID_GENDERS = ('F', 'M', 'U')
VALID_AGE_BANDS = ('<18', '18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'U')
VALID_LINK_STATUSES = ('active', 'removed')

def utcnow():
    return datetime.now(timezone.utc)

class Farmer(Base):
    __tablename__ = "farmer"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    hash_key = Column(String(64), unique=True, nullable=False, index=True)
    gender = Column(String(5), nullable=False)
    age_band = Column(String(10), nullable=False)
    county_code = Column(String(10), nullable=False, index=True)
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


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    action = Column(String(50), nullable=False)
    partner_id = Column(String(50), nullable=False)
    farmer_id = Column(Integer, nullable=True)  # Strictly farmer_id or NULL; NEVER store incoming hash or phone!
    at = Column(DateTime, default=utcnow, nullable=False)
