import hmac
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Farmer, PartnerLink, Partner, FarmerEntity, PartnerAssociation, FarmerConsent
from app.config import settings

BASE_DIR = Path(__file__).resolve().parent.parent
router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
security = HTTPBasic()

def authenticate_dashboard(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = hmac.compare_digest(credentials.username.encode("utf-8"), settings.DASHBOARD_USER.encode("utf-8"))
    correct_pass = False
    if settings.DASHBOARD_PASSWORD:
        dash_pwd = settings.DASHBOARD_PASSWORD.get_secret_value() if hasattr(settings.DASHBOARD_PASSWORD, "get_secret_value") else str(settings.DASHBOARD_PASSWORD)
        correct_pass = hmac.compare_digest(credentials.password.encode("utf-8"), dash_pwd.encode("utf-8"))
        
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect dashboard credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def apply_k_anonymity(count: int, threshold: int = settings.SUPPRESSION_THRESHOLD) -> dict:
    if 0 < count < threshold:
        return {"value": 0, "display": "<5", "suppressed": True}
    return {"value": count, "display": str(count), "suppressed": False}

@router.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(
    request: Request,
    _auth: str = Depends(authenticate_dashboard),
    db: Session = Depends(get_db)
):
    total_registrations = db.query(PartnerLink).filter(PartnerLink.status == "active").count()
    unique_farmers = db.query(Farmer).join(PartnerLink).filter(PartnerLink.status == "active").distinct().count()

    total_entities = db.query(FarmerEntity).filter(FarmerEntity.status == "active").count()
    total_associations = (
        db.query(PartnerAssociation)
        .join(FarmerEntity, PartnerAssociation.entity_id == FarmerEntity.entity_id)
        .filter(PartnerAssociation.status == "active", FarmerEntity.status == "active")
        .count()
    )
    active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
    withdrawn_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()

    if total_associations > 0:
        total_registrations = total_associations
        unique_farmers = total_entities
    
    overlap_rate = 0.0
    if total_registrations > 0:
        overlap_rate = round((1.0 - (unique_farmers / total_registrations)) * 100.0, 2)
        
    gender_rows = db.query(Farmer.gender, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.gender).all()
    
    gender_counts = {}
    for g, cnt in gender_rows:
        label = {"F": "Female (F)", "M": "Male (M)", "U": "Unknown (U)"}.get(g, g)
        gender_counts[label] = apply_k_anonymity(cnt)

    age_bands_order = ['<18', '18-24', '25-34', '35-44', '45-54', '55-64', '65+', 'U']
    age_rows = db.query(Farmer.age_band, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.age_band).all()
    age_dict = dict(age_rows)
    age_counts = {band: apply_k_anonymity(age_dict.get(band, 0)) for band in age_bands_order}

    county_rows = db.query(Farmer.county_code, func.count(Farmer.id))\
        .join(PartnerLink).filter(PartnerLink.status == "active")\
        .group_by(Farmer.county_code).order_by(func.count(Farmer.id).desc()).all()
    county_counts = {c: apply_k_anonymity(cnt) for c, cnt in county_rows}

    all_partners = db.query(Partner.partner_id, Partner.name).all()
    partner_names = {p.partner_id: p.name for p in all_partners}
    
    earliest_links = db.query(
        PartnerLink.farmer_id,
        PartnerLink.partner_id,
        PartnerLink.received_at
    ).filter(PartnerLink.status == "active").order_by(PartnerLink.farmer_id, PartnerLink.received_at.asc()).all()
    
    seen_farmers = set()
    first_onboard_counts = defaultdict(int)
    for fl in earliest_links:
        if fl.farmer_id not in seen_farmers:
            seen_farmers.add(fl.farmer_id)
            first_onboard_counts[fl.partner_id] += 1
            
    first_credit = {}
    for pid, name in partner_names.items():
        first_credit[f"{name} ({pid})"] = apply_k_anonymity(first_onboard_counts.get(pid, 0))

    farmers = db.query(Farmer.created_at).all()
    weekly_buckets = defaultdict(int)
    for f in farmers:
        if f.created_at:
            week_key = f.created_at.strftime("%Y-W%W")
            weekly_buckets[week_key] += 1
            
    sorted_weeks = sorted(weekly_buckets.keys())
    weekly_trend = {w: apply_k_anonymity(weekly_buckets[w]) for w in sorted_weeks}

    total_entities = db.query(FarmerEntity).filter(FarmerEntity.status == "active").count()
    total_associations = (
        db.query(PartnerAssociation)
        .join(FarmerEntity, PartnerAssociation.entity_id == FarmerEntity.entity_id)
        .filter(PartnerAssociation.status == "active", FarmerEntity.status == "active")
        .count()
    )
    active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
    withdrawn_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "total_registrations": total_registrations,
            "unique_farmers": unique_farmers,
            "overlap_rate": overlap_rate,
            "total_entities": total_entities or unique_farmers,
            "total_associations": total_associations or total_registrations,
            "active_consents": active_consents,
            "withdrawn_consents": withdrawn_consents,
            "gender_counts": gender_counts,
            "age_counts": age_counts,
            "county_counts": county_counts,
            "first_credit": first_credit,
            "weekly_trend": weekly_trend,
            "threshold": settings.SUPPRESSION_THRESHOLD
        }
    )

@router.get("/v1/telemetry/dpi-metrics")
def get_dpi_telemetry_metrics(
    _auth: str = Depends(authenticate_dashboard),
    db: Session = Depends(get_db)
):
    """
    Returns live verified DPI Deduplication & Consent Telemetry.
    """
    total_registrations = (
        db.query(PartnerAssociation)
        .join(FarmerEntity, PartnerAssociation.entity_id == FarmerEntity.entity_id)
        .filter(PartnerAssociation.status == "active", FarmerEntity.status == "active")
        .count()
    )
    dedup_identities = db.query(FarmerEntity).filter(FarmerEntity.status == "active").count()

    if total_registrations == 0:
        total_registrations = db.query(PartnerLink).filter(PartnerLink.status == "active").count()
        dedup_identities = db.query(Farmer).join(PartnerLink).filter(PartnerLink.status == "active").distinct().count()

    overlap_count = max(0, total_registrations - dedup_identities)
    overlap_rate = round((overlap_count / total_registrations * 100.0), 2) if total_registrations > 0 else 0.0

    active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
    withdrawn_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()

    return {
        "total_registrations_received": total_registrations,
        "deduplicated_farmer_identities": dedup_identities,
        "cross_provider_overlap_records": overlap_count,
        "cross_provider_overlap_rate_pct": overlap_rate,
        "consent_active_count": active_consents,
        "consent_withdrawn_count": withdrawn_consents
    }
