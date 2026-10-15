import os
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Farmer, PartnerLink, Partner
from app.hashing import hash_api_key
from sdk.python.hasher import hash_phone

router = APIRouter(prefix="/dev", tags=["Development Console"])

def check_development_mode():
    if settings.ENV != "development":
        raise HTTPException(status_code=404, detail="Dev console is only accessible when ENV=development")

@router.get("/console", response_class=HTMLResponse)
def get_dev_console(request: Request):
    check_development_mode()
    from app.routes.dashboard import templates
    return templates.TemplateResponse(
        request=request,
        name="dev_console.html",
        context={
            "env": settings.ENV,
            "pilot_start_date": settings.PILOT_START_DATE
        }
    )


@router.get("/unsuppressed-metrics")
def get_unsuppressed_metrics(db: Session = Depends(get_db)):
    check_development_mode()
    total_farmers = db.query(Farmer).count()
    active_links = db.query(PartnerLink).filter(PartnerLink.status == "active").count()
    removed_links = db.query(PartnerLink).filter(PartnerLink.status == "removed").count()

    partners = db.query(Partner).all()
    partner_stats = []
    for p in partners:
        p_links = db.query(PartnerLink).filter(
            PartnerLink.partner_id == p.partner_id,
            PartnerLink.status == "active"
        ).count()
        partner_stats.append({
            "partner_id": p.partner_id,
            "name": p.name,
            "active": bool(p.active),
            "active_links": p_links
        })

    # Recent links
    recent_links = (
        db.query(PartnerLink)
        .order_by(PartnerLink.received_at.desc())
        .limit(15)
        .all()
    )
    events = []
    for l in recent_links:
        f_code = (l.farmer.hash_key[:12] + "...") if l.farmer else "unknown"

        county = l.farmer.county_code if l.farmer else "-"
        events.append({
            "partner_id": l.partner_id,
            "farmer_code": f_code,
            "county_code": county,
            "onboarded_at": l.linked_at.isoformat() if l.linked_at else None,
            "received_at": l.received_at.isoformat() if l.received_at else None,
            "status": l.status
        })


    return {
        "total_unique_farmers": total_farmers,
        "total_active_links": active_links,
        "total_removed_links": removed_links,
        "partners": partner_stats,
        "recent_links": events
    }

@router.get("/sample-csv")
def get_sample_csv():
    check_development_mode()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "samples", "sample_registration_batch.csv")
    if os.path.exists(sample_path):
        return FileResponse(sample_path, media_type="text/csv", filename="sample_registration_batch.csv")
    raise HTTPException(status_code=404, detail="Sample CSV not found")
