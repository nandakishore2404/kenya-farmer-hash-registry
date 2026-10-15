from datetime import datetime, timezone
from collections import defaultdict
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Farmer, PartnerLink, Partner
from app.config import settings

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")

def apply_k_anonymity(count: int, threshold: int = settings.SUPPRESSION_THRESHOLD):
    """
    Suppresses any count under 5 to protect individual privacy.
    Returns 0 or '<5' string representation.
    """
    if 0 < count < threshold:
        return 0  # In chart data, suppress to 0 or group
    return count

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request, db: Session = Depends(get_db)):
    # 1. Total registrations (all active partner links)
    total_registrations = db.query(PartnerLink).filter(PartnerLink.status == "active").count()
    
    # 2. Unique farmers (active farmers with at least one active partner link)
    unique_farmers = db.query(Farmer).join(PartnerLink).filter(PartnerLink.status == "active").distinct().count()
    
    # 3. Overlap rate = 1 - (unique / registrations)
    overlap_rate = 0.0
    if total_registrations > 0:
        overlap_rate = round((1.0 - (unique_farmers / total_registrations)) * 100.0, 2)
        
    # 4. Gender distribution
    gender_rows = db.query(Farmer.gender, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.gender).all()
    
    gender_counts = {}
    for g, cnt in gender_rows:
        label = {"F": "Female (F)", "M": "Male (M)", "U": "Unknown (U)"}.get(g, g)
        gender_counts[label] = apply_k_anonymity(cnt)

    # 5. Age band distribution
    age_bands_order = ['<18', '18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'U']
    age_rows = db.query(Farmer.age_band, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.age_band).all()
    age_dict = dict(age_rows)
    age_counts = {band: apply_k_anonymity(age_dict.get(band, 0)) for band in age_bands_order}

    # 6. County distribution
    county_rows = db.query(Farmer.county_code, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.county_code).order_by(func.count(Farmer.id).desc()).all()
    county_counts = {c: apply_k_anonymity(cnt) for c, cnt in county_rows}

    # 7. First-to-onboard credit per partner
    all_partners = db.query(Partner.partner_id, Partner.name).all()
    partner_names = {p.partner_id: p.name for p in all_partners}
    
    # For each active farmer, find the earliest partner link
    earliest_links = db.query(
        PartnerLink.farmer_id,
        PartnerLink.partner_id,
        PartnerLink.linked_at
    ).filter(PartnerLink.status == "active").order_by(PartnerLink.farmer_id, PartnerLink.linked_at.asc()).all()
    
    seen_farmers = set()
    first_onboard_counts = defaultdict(int)
    for fl in earliest_links:
        if fl.farmer_id not in seen_farmers:
            seen_farmers.add(fl.farmer_id)
            first_onboard_counts[fl.partner_id] += 1
            
    first_credit = {}
    for pid, name in partner_names.items():
        first_credit[f"{name} ({pid})"] = apply_k_anonymity(first_onboard_counts.get(pid, 0))

    # 8. Weekly trend
    farmers = db.query(Farmer.created_at).all()
    weekly_buckets = defaultdict(int)
    for f in farmers:
        if f.created_at:
            # Format as YYYY-WW
            week_key = f.created_at.strftime("%Y-W%W")
            weekly_buckets[week_key] += 1
            
    sorted_weeks = sorted(weekly_buckets.keys())
    weekly_trend = {w: apply_k_anonymity(weekly_buckets[w]) for w in sorted_weeks}

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "total_registrations": total_registrations,
            "unique_farmers": unique_farmers,
            "overlap_rate": overlap_rate,
            "gender_counts": gender_counts,
            "age_counts": age_counts,
            "county_counts": county_counts,
            "first_credit": first_credit,
            "weekly_trend": weekly_trend,
            "threshold": settings.SUPPRESSION_THRESHOLD
        }
    )
