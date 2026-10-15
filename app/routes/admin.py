from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Farmer, PartnerLink, AuditLog
from app.schemas import AdminLookupResponse, PartnerLinkDetail
from app.hashing import rekey_hash
from app.auth import authenticate_admin

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/lookup", response_model=AdminLookupResponse)
def admin_lookup(
    hash: str = Query(..., description="Incoming partner hash to look up"),
    _admin: bool = Depends(authenticate_admin),
    db: Session = Depends(get_db)
):
    """
    Admin-only lookup:
    Returns which partners are linked to the farmer corresponding to the hash.
    Every call is recorded in audit_log.
    """
    hash_key = rekey_hash(hash)
    farmer = db.query(Farmer).filter(Farmer.hash_key == hash_key).first()
    
    now = datetime.now(timezone.utc)
    
    if not farmer:
        # Audit even failed lookup
        audit = AuditLog(
            action="admin_lookup_not_found",
            partner_id="admin",
            farmer_id=None,
            at=now
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Farmer not found"
        )
    
    # Audit successful lookup
    audit = AuditLog(
        action="admin_lookup",
        partner_id="admin",
        farmer_id=farmer.id,
        at=now
    )
    db.add(audit)
    db.commit()
    
    links = db.query(PartnerLink).filter(PartnerLink.farmer_id == farmer.id).all()
    partner_details = [
        PartnerLinkDetail(
            partner_id=link.partner_id,
            status=link.status,
            linked_at=link.linked_at
        )
        for link in links
    ]
    
    return AdminLookupResponse(
        farmer_id=farmer.id,
        created_at=farmer.created_at,
        partners=partner_details
    )
