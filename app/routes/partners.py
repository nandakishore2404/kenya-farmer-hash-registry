from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import PartnerLink, Farmer, Partner
from app.schemas import PartnerSummaryResponse
from app.auth import authenticate_partner

router = APIRouter(prefix="/v1/partners", tags=["partners"])

@router.get("/me/summary", response_model=PartnerSummaryResponse)
def get_partner_summary(
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Returns the calling partner's own totals only:
    - farmers sent (active links)
    - of which first-to-onboard
    - of which already known
    Aggregate numbers only, never lists.
    """
    # Active links for this partner
    active_links = db.query(PartnerLink).filter(
        PartnerLink.partner_id == partner.partner_id,
        PartnerLink.status == "active"
    ).all()
    
    total_sent = len(active_links)
    first_to_onboard = 0
    already_known = 0
    
    for link in active_links:
        # Determine the earliest received_at for this farmer
        earliest_link = db.query(PartnerLink).filter(
            PartnerLink.farmer_id == link.farmer_id,
            PartnerLink.status == "active"
        ).order_by(PartnerLink.received_at.asc(), PartnerLink.id.asc()).first()
        
        if earliest_link and earliest_link.partner_id == partner.partner_id:
            first_to_onboard += 1
        else:
            already_known += 1
            
    return PartnerSummaryResponse(
        partner_id=partner.partner_id,
        farmers_sent=total_sent,
        first_to_onboard=first_to_onboard,
        already_known=already_known
    )
