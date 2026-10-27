"""
OAN Kenya Temporary Farmer Registry & Consent Microservice
Implements:
  1. RFC 9497 Token Storage Transformation: D = HMAC(storage_key, T)
  2. Multi-Key Entity Deduplication & Aliasing
  3. Decoupled Provider Attribution Layer
  4. First-Class Consent Lifecycle & Policy Enforcement Point (PEP)
  5. Privacy-Preserving DPI Telemetry & Overlap Metrics
"""

import hmac
import hashlib
import base64
from datetime import datetime, timezone
from typing import List, Optional, Literal
from fastapi import FastAPI, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session

from prototype_voprf.crypto.voprf_engine import length_prefix
from prototype_voprf.registry.models import (
    Base,
    FarmerEntity,
    TokenAlias,
    PartnerAssociation,
    FarmerConsent,
    AuditLog
)

# Registry Storage Secret Key (Isolated from Evaluator Key k)
REGISTRY_STORAGE_KEY = b"OAN-REGISTRY-STORAGE-SECRET-KEY-2026-PILOT"

# In-memory SQLite for prototype demonstration
engine = create_engine("sqlite:///./prototype_registry.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="OAN Kenya Temporary Farmer Registry & Consent Gateway", version="1.0.0")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def compute_storage_digest(pilot_id: str, key_id: str, token_bytes: bytes) -> str:
    """
    Transforms raw token T into storage digest D:
    D = HMAC-SHA256(registry_storage_key, LP("oan-registry-v1") || LP(pilot_id) || LP(key_id) || T)
    Ensures raw token T is never persisted directly.
    """
    msg = (
        length_prefix("oan-registry-v1")
        + length_prefix(pilot_id)
        + length_prefix(key_id)
        + token_bytes
    )
    return hmac.new(REGISTRY_STORAGE_KEY, msg, hashlib.sha256).hexdigest()

# Partner authentication simulation
PARTNER_DIRECTORY = {
    "partner_oaf_token": "One Acre Fund",
    "partner_digifarm_token": "DigiFarm",
    "partner_ktda_token": "KTDA",
    "partner_whitelabel_token": "OAN White-Label Gateway"
}

def authenticate_partner(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    tok = authorization.split(" ")[1]
    if tok not in PARTNER_DIRECTORY:
        raise HTTPException(status_code=403, detail="Unauthorized partner credential")
    return PARTNER_DIRECTORY[tok]

# Schemas
class RegistrationRequest(BaseModel):
    pilot_id: str = "kenya-pilot"
    key_id: str = "ke-pilot-v1"
    token_b64: str = Field(..., description="Base64-encoded 64-byte finalized VOPRF token T")
    idempotency_key: str = Field(..., description="Unique UUID per client submission")
    role: Optional[Literal["onboarder", "primary", "contributor"]] = "contributor"
    onboarded_at: Optional[datetime] = None

class RegistrationResponse(BaseModel):
    status: str = "accepted"
    entity_id: str
    is_new_entity: bool
    partner_association_status: str

class ConsentCaptureRequest(BaseModel):
    entity_id: str
    purpose: Literal["ADVISORY", "FERTILIZER_SUBSIDY", "PEST_ALERT"] = "ADVISORY"
    version: str = "v1.0"
    channel: Literal["WHITE_LABEL_APP", "USSD", "PARTNER_API"] = "WHITE_LABEL_APP"
    evidence_ref: Optional[str] = "digital_affirmation_v1"

class ConsentWithdrawRequest(BaseModel):
    entity_id: str
    purpose: Literal["ADVISORY", "FERTILIZER_SUBSIDY", "PEST_ALERT"] = "ADVISORY"
    reason: Optional[str] = "User requested opt-out via USSD"

class ConsentCheckResponse(BaseModel):
    entity_id: str
    purpose: str
    allowed: bool
    status: str

@app.post("/v1/registrations", response_model=RegistrationResponse)
def register_farmer(
    req: RegistrationRequest,
    partner_name: str = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Deduplicates and registers a farmer token.
    1. Computes storage digest D from token T.
    2. Atomically checks token_alias table.
    3. Resolves existing FarmerEntity or creates a new one.
    4. Upserts PartnerAssociation without overwriting first-onboarder attribution.
    """
    try:
        raw_token = base64.b64decode(req.token_b64)
        if len(raw_token) != 64:
            raise ValueError("Token must be exactly 64 bytes")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 token format")

    digest_d = compute_storage_digest(req.pilot_id, req.key_id, raw_token)

    # 1. Look up existing alias
    existing_alias = db.query(TokenAlias).filter(
        TokenAlias.pilot_id == req.pilot_id,
        TokenAlias.key_id == req.key_id,
        TokenAlias.digest_d == digest_d
    ).first()

    now = datetime.now(timezone.utc)
    is_new_entity = False

    if not existing_alias:
        # Create new FarmerEntity
        entity = FarmerEntity(created_at=now, updated_at=now, status="active")
        db.add(entity)
        db.flush()

        # Add TokenAlias
        alias = TokenAlias(
            entity_id=entity.entity_id,
            pilot_id=req.pilot_id,
            scheme="voprf_ristretto255",
            key_id=req.key_id,
            digest_d=digest_d,
            created_at=now
        )
        db.add(alias)

        # Primary onboarding attribution
        assoc = PartnerAssociation(
            entity_id=entity.entity_id,
            partner_id=partner_name,
            role="onboarder",
            first_seen=now,
            last_seen=now,
            status="active"
        )
        db.add(assoc)

        # Audit
        db.add(AuditLog(
            event_type="REGISTER_FIRST",
            entity_id=entity.entity_id,
            partner_id=partner_name,
            details=f"New entity created by {partner_name}"
        ))
        is_new_entity = True
        resolved_entity_id = entity.entity_id
    else:
        resolved_entity_id = existing_alias.entity_id
        # Farmer is already known in registry!
        # Check if caller already has an association
        assoc = db.query(PartnerAssociation).filter(
            PartnerAssociation.entity_id == resolved_entity_id,
            PartnerAssociation.partner_id == partner_name
        ).first()

        if not assoc:
            # Second or third partner serving the same farmer! Overlap detected!
            assoc = PartnerAssociation(
                entity_id=resolved_entity_id,
                partner_id=partner_name,
                role=req.role or "contributor",
                first_seen=now,
                last_seen=now,
                status="active"
            )
            db.add(assoc)
            db.add(AuditLog(
                event_type="REGISTER_OVERLAP",
                entity_id=resolved_entity_id,
                partner_id=partner_name,
                details=f"Cross-provider overlap: {partner_name} linked to existing entity"
            ))
        else:
            # Idempotent re-send: update last_seen
            assoc.last_seen = now
            assoc.status = "active"
            db.add(AuditLog(
                event_type="REGISTER_IDEMPOTENT_RESEND",
                entity_id=resolved_entity_id,
                partner_id=partner_name,
                details="Idempotent re-registration; attribution preserved"
            ))

    db.commit()

    return RegistrationResponse(
        status="accepted",
        entity_id=resolved_entity_id,
        is_new_entity=is_new_entity,
        partner_association_status=assoc.status
    )

@app.post("/v1/consent/capture")
def capture_consent(
    req: ConsentCaptureRequest,
    partner_name: str = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Captures or re-activates consent for an entity and purpose.
    """
    entity = db.query(FarmerEntity).filter(FarmerEntity.entity_id == req.entity_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Farmer entity not found")

    now = datetime.now(timezone.utc)
    # Check existing consent record for this entity and purpose
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == req.entity_id,
        FarmerConsent.purpose == req.purpose
    ).first()

    if not consent:
        consent = FarmerConsent(
            entity_id=req.entity_id,
            partner_id=partner_name,
            purpose=req.purpose,
            status="ACTIVE",
            version=req.version,
            channel=req.channel,
            evidence_ref=req.evidence_ref,
            captured_at=now
        )
        db.add(consent)
    else:
        # Re-consent restores ACTIVE status without mutating identity!
        consent.status = "ACTIVE"
        consent.withdrawn_at = None
        consent.withdrawal_reason = None
        consent.captured_at = now
        consent.version = req.version

    db.add(AuditLog(
        event_type="CONSENT_CAPTURED",
        entity_id=req.entity_id,
        partner_id=partner_name,
        details=f"Consent granted for {req.purpose} via {req.channel}"
    ))
    db.commit()
    return {"status": "success", "consent_id": consent.consent_id, "state": "ACTIVE"}

@app.post("/v1/consent/withdraw")
def withdraw_consent(
    req: ConsentWithdrawRequest,
    partner_name: str = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Withdraws consent for an entity and purpose.
    Immediately stops all downstream consent-dependent processing.
    """
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == req.entity_id,
        FarmerConsent.purpose == req.purpose
    ).first()

    if not consent:
        raise HTTPException(status_code=404, detail="No active consent found for this entity and purpose")

    now = datetime.now(timezone.utc)
    consent.status = "WITHDRAWN"
    consent.withdrawn_at = now
    consent.withdrawal_reason = req.reason

    db.add(AuditLog(
        event_type="CONSENT_WITHDRAWN",
        entity_id=req.entity_id,
        partner_id=partner_name,
        details=f"Consent revoked for {req.purpose}. Reason: {req.reason}"
    ))
    db.commit()
    return {"status": "success", "consent_id": consent.consent_id, "state": "WITHDRAWN"}

@app.get("/v1/consent/check", response_model=ConsentCheckResponse)
def check_consent_enforcement_point(
    entity_id: str,
    purpose: str = "ADVISORY",
    db: Session = Depends(get_db)
):
    """
    Policy Enforcement Point (PEP) for Downstream OAN Services:
    Must be called before advisory messages, pest alerts, or subsidies are dispatched.
    Returns: ALLOW (true) if ACTIVE, BLOCK (false) if WITHDRAWN or missing.
    """
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == entity_id,
        FarmerConsent.purpose == purpose
    ).first()

    if not consent or consent.status != "ACTIVE":
        return ConsentCheckResponse(
            entity_id=entity_id,
            purpose=purpose,
            allowed=False,
            status=consent.status if consent else "NO_CONSENT_RECORD"
        )

    return ConsentCheckResponse(
        entity_id=entity_id,
        purpose=purpose,
        allowed=True,
        status="ACTIVE"
    )

@app.get("/v1/metrics")
def get_dpi_telemetry(db: Session = Depends(get_db)):
    """
    Calculates verified DPI metrics:
    - Total registrations received
    - Deduplicated farmer identities
    - Cross-provider overlap count and rate
    - Active vs Withdrawn consent totals
    - Overlap distribution across partners
    """
    total_registrations = db.query(PartnerAssociation).filter(PartnerAssociation.status == "active").count()
    deduplicated_identities = db.query(FarmerEntity).filter(FarmerEntity.status == "active").count()

    overlap_count = max(0, total_registrations - deduplicated_identities)
    overlap_rate = round((overlap_count / total_registrations * 100.0), 2) if total_registrations > 0 else 0.0

    # Multi-provider farmers (associated with >1 partner)
    shared_farmers_query = db.query(
        PartnerAssociation.entity_id
    ).filter(
        PartnerAssociation.status == "active"
    ).group_by(
        PartnerAssociation.entity_id
    ).having(func.count(PartnerAssociation.partner_id) > 1).count()

    # Consent breakdown
    active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
    withdrawn_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()

    return {
        "total_registrations_received": total_registrations,
        "deduplicated_farmer_identities": deduplicated_identities,
        "cross_provider_overlap_records": overlap_count,
        "cross_provider_overlap_rate_pct": overlap_rate,
        "farmers_shared_across_multiple_providers": shared_farmers_query,
        "consent_active_count": active_consents,
        "consent_withdrawn_count": withdrawn_consents
    }
