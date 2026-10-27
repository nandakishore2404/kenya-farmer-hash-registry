"""
First-Class Farmer Consent Registry & Policy Enforcement Point (PEP)
Provides:
  - POST /v1/consent/capture: Captures active purpose-aware consent
  - POST /v1/consent/withdraw: Revokes consent and blocks downstream processing
  - GET  /v1/consent/check: PEP for downstream advisory/messaging services
  - GET  /v1/consent/status: Retrieves consent lifecycle state
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import authenticate_partner
from app.models import FarmerEntity, FarmerConsent, AuditLog, Partner

router = APIRouter(prefix="/v1/consent", tags=["consent"])

class ConsentCaptureRequest(BaseModel):
    entity_id: str = Field(..., description="Target Farmer Entity UUID")
    purpose: Literal["ADVISORY", "FERTILIZER_SUBSIDY", "PEST_ALERT"] = "ADVISORY"
    version: str = Field("v1.0", description="Consent document version presented")
    channel: Literal["WHITE_LABEL_APP", "USSD", "PARTNER_API", "PAPER_FORM"] = "WHITE_LABEL_APP"
    evidence_ref: Optional[str] = "digital_affirmation_v1"

class ConsentWithdrawRequest(BaseModel):
    entity_id: str
    purpose: Literal["ADVISORY", "FERTILIZER_SUBSIDY", "PEST_ALERT"] = "ADVISORY"
    reason: Optional[str] = "Farmer requested opt-out via USSD/SMS"

class ConsentCheckResponse(BaseModel):
    entity_id: str
    purpose: str
    allowed: bool
    status: str

@router.post("/capture")
def capture_consent(
    req: ConsentCaptureRequest,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Captures or re-activates consent for a farmer entity.
    """
    entity = db.query(FarmerEntity).filter(FarmerEntity.entity_id == req.entity_id).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Farmer entity not found")

    now = datetime.now(timezone.utc)
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == req.entity_id,
        FarmerConsent.purpose == req.purpose
    ).first()

    if not consent:
        consent = FarmerConsent(
            entity_id=req.entity_id,
            partner_id=partner.partner_id,
            purpose=req.purpose,
            status="ACTIVE",
            version=req.version,
            channel=req.channel,
            evidence_ref=req.evidence_ref,
            captured_at=now
        )
        db.add(consent)
    else:
        consent.status = "ACTIVE"
        consent.withdrawn_at = None
        consent.withdrawal_reason = None
        consent.captured_at = now
        consent.version = req.version

    db.add(AuditLog(
        action="consent_captured",
        partner_id=partner.partner_id,
        entity_id=req.entity_id,
        at=now
    ))
    db.commit()
    return {"status": "success", "consent_id": consent.consent_id, "state": "ACTIVE"}

@router.post("/withdraw")
def withdraw_consent(
    req: ConsentWithdrawRequest,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Withdraws consent. Downstream advisory services must immediately block processing.
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
        action="consent_withdrawn",
        partner_id=partner.partner_id,
        entity_id=req.entity_id,
        at=now
    ))
    db.commit()
    return {"status": "success", "consent_id": consent.consent_id, "state": "WITHDRAWN"}

@router.get("/check", response_model=ConsentCheckResponse)
def check_consent_policy_enforcement_point(
    entity_id: str,
    purpose: str = "ADVISORY",
    db: Session = Depends(get_db)
):
    """
    Common Consent Policy Enforcement Point (PEP):
    Mandatory pre-flight check before any advisory, SMS, or subsidy service executes.
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

@router.get("/status")
def get_consent_status(
    entity_id: str,
    purpose: str = "ADVISORY",
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == entity_id,
        FarmerConsent.purpose == purpose
    ).first()
    if not consent:
        raise HTTPException(status_code=404, detail="No consent record found")
    return {
        "consent_id": consent.consent_id,
        "entity_id": consent.entity_id,
        "purpose": consent.purpose,
        "status": consent.status,
        "captured_at": consent.captured_at.isoformat() if consent.captured_at else None,
        "withdrawn_at": consent.withdrawn_at.isoformat() if consent.withdrawn_at else None
    }
