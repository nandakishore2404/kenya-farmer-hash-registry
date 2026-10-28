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
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import authenticate_partner
from app.models import FarmerEntity, FarmerConsent, AuditLog, Partner, PartnerAssociation

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
        FarmerConsent.partner_id == partner.partner_id,
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
        FarmerConsent.partner_id == partner.partner_id,
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
    on_behalf_of_partner_id: Optional[str] = None,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Common Consent Policy Enforcement Point (PEP):
    Mandatory pre-flight check before any advisory, SMS, or subsidy service executes.
    Requires partner authentication (or internal service credentials).
    - Internal services MUST provide on_behalf_of_partner_id (HTTP 400 if omitted).
    - Scopes consent check strictly to that governing partner.
    - Validates target partner exists, is active, and has an active PartnerAssociation with entity (HTTP 403 otherwise).
    - Records on_behalf_of_partner_id in AuditLog.
    Returns: ALLOW (true) if ACTIVE, BLOCK (false) if WITHDRAWN or missing.
    """
    is_internal = getattr(partner, "is_internal_service", 0) == 1
    on_behalf_clean = on_behalf_of_partner_id.strip() if isinstance(on_behalf_of_partner_id, str) and on_behalf_of_partner_id.strip() else None

    if is_internal:
        if not on_behalf_clean:
            raise HTTPException(
                status_code=400,
                detail="Bad Request: Internal services must supply 'on_behalf_of_partner_id' to evaluate governing consent."
            )
        target_partner_id = on_behalf_clean
        target_partner = db.query(Partner).filter(Partner.partner_id == target_partner_id).first()
        if not target_partner or target_partner.active != 1:
            raise HTTPException(
                status_code=404,
                detail=f"Target partner '{target_partner_id}' not found or is disabled."
            )
    else:
        if on_behalf_clean and on_behalf_clean != partner.partner_id:
            raise HTTPException(
                status_code=400,
                detail="Bad Request: External delivery partners cannot query on behalf of other partners."
            )
        target_partner_id = partner.partner_id

    # 1. Partner Authorization: Verify target partner has an active association with entity
    assoc = db.query(PartnerAssociation).filter(
        PartnerAssociation.entity_id == entity_id,
        PartnerAssociation.partner_id == target_partner_id,
        PartnerAssociation.status == "active"
    ).first()
    if not assoc:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Partner '{target_partner_id}' does not have an active association with entity '{entity_id}'."
        )

    # 2. Scope consent lookup strictly to target partner
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == entity_id,
        FarmerConsent.partner_id == target_partner_id,
        FarmerConsent.purpose == purpose
    ).first()

    # Log PEP check in AuditLog
    now = datetime.now(timezone.utc)
    db.add(AuditLog(
        action="consent_pep_check",
        partner_id=partner.partner_id,
        entity_id=entity_id,
        on_behalf_of_partner_id=target_partner_id if is_internal else None,
        at=now
    ))
    db.commit()

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
    on_behalf_of_partner_id: Optional[str] = None,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    is_internal = getattr(partner, "is_internal_service", 0) == 1
    on_behalf_clean = on_behalf_of_partner_id.strip() if isinstance(on_behalf_of_partner_id, str) and on_behalf_of_partner_id.strip() else None

    if is_internal:
        if not on_behalf_clean:
            raise HTTPException(
                status_code=400,
                detail="Bad Request: Internal services must supply 'on_behalf_of_partner_id' to evaluate governing consent."
            )
        target_partner_id = on_behalf_clean
        target_partner = db.query(Partner).filter(Partner.partner_id == target_partner_id).first()
        if not target_partner or target_partner.active != 1:
            raise HTTPException(
                status_code=404,
                detail=f"Target partner '{target_partner_id}' not found or is disabled."
            )
    else:
        if on_behalf_clean and on_behalf_clean != partner.partner_id:
            raise HTTPException(
                status_code=400,
                detail="Bad Request: External delivery partners cannot query on behalf of other partners."
            )
        target_partner_id = partner.partner_id

    assoc = db.query(PartnerAssociation).filter(
        PartnerAssociation.entity_id == entity_id,
        PartnerAssociation.partner_id == target_partner_id,
        PartnerAssociation.status == "active"
    ).first()
    if not assoc:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Partner '{target_partner_id}' does not have an active association with entity '{entity_id}'."
        )

    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == entity_id,
        FarmerConsent.partner_id == target_partner_id,
        FarmerConsent.purpose == purpose
    ).first()

    now = datetime.now(timezone.utc)
    db.add(AuditLog(
        action="consent_pep_check",
        partner_id=partner.partner_id,
        entity_id=entity_id,
        on_behalf_of_partner_id=target_partner_id if is_internal else None,
        at=now
    ))
    db.commit()

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
