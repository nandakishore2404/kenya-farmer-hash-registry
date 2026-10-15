import csv
import io
import re
import email
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Farmer, PartnerLink, AuditLog, Partner, VALID_GENDERS, VALID_AGE_BANDS
from app.schemas import FarmerRegisterRequest, StatusAcceptedResponse, UploadResponse
from app.hashing import rekey_hash
from app.auth import authenticate_partner

router = APIRouter(prefix="/v1/farmers", tags=["farmers"])

HEX_64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

def parse_iso_datetime(dt_str: Optional[str]) -> datetime:
    if not dt_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)

def process_farmer_registration(
    db: Session,
    partner_id: str,
    incoming_hash: str,
    gender: str,
    age_band: str,
    county_code: str,
    onboarded_at: Optional[datetime] = None
) -> None:
    now = datetime.now(timezone.utc)
    # Validate onboarded_at bounds if provided
    if onboarded_at:
        dt = onboarded_at if onboarded_at.tzinfo else onboarded_at.replace(tzinfo=timezone.utc)
        from datetime import timedelta
        if dt > now + timedelta(minutes=5):
            raise ValueError("onboarded_at cannot be more than 5 minutes in the future")
        from app.config import settings
        pilot_start = datetime.fromisoformat(settings.PILOT_START_DATE).replace(tzinfo=timezone.utc)
        if dt < pilot_start:
            raise ValueError("onboarded_at cannot be earlier than pilot start date")
        ts = dt
    else:
        ts = now
        
    hash_key = rekey_hash(incoming_hash)
    
    farmer = db.query(Farmer).filter(Farmer.hash_key == hash_key).first()
    
    if not farmer:
        # First partner onboarding this farmer
        new_farmer = Farmer(
            hash_key=hash_key,
            gender=gender,
            age_band=age_band,
            county_code=county_code,
            created_at=now,
            updated_at=now
        )
        db.add(new_farmer)
        db.flush()
        
        new_link = PartnerLink(
            farmer_id=new_farmer.id,
            partner_id=partner_id,
            linked_at=ts,
            received_at=now,
            status="active"
        )
        db.add(new_link)
        
        audit = AuditLog(
            action="register_first",
            partner_id=partner_id,
            farmer_id=new_farmer.id,
            at=now
        )
        db.add(audit)
    else:
        # Farmer already known in registry
        link = db.query(PartnerLink).filter(
            PartnerLink.farmer_id == farmer.id,
            PartnerLink.partner_id == partner_id
        ).first()
        
        if link:
            if link.status == "active":
                # Idempotent re-send: no change
                audit = AuditLog(
                    action="register_duplicate_same_partner",
                    partner_id=partner_id,
                    farmer_id=farmer.id,
                    at=now
                )
                db.add(audit)
            else:
                # Previously removed, now reactivated
                link.status = "active"
                link.linked_at = ts
                link.received_at = now
                audit = AuditLog(
                    action="register_reactivate_partner",
                    partner_id=partner_id,
                    farmer_id=farmer.id,
                    at=now
                )
                db.add(audit)
        else:
            # New partner linking to existing farmer
            new_link = PartnerLink(
                farmer_id=farmer.id,
                partner_id=partner_id,
                linked_at=ts,
                received_at=now,
                status="active"
            )
            db.add(new_link)
            audit = AuditLog(
                action="register_link_existing",
                partner_id=partner_id,
                farmer_id=farmer.id,
                at=now
            )
            db.add(audit)


@router.post("", response_model=StatusAcceptedResponse)
def register_farmer(
    payload: FarmerRegisterRequest,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Registers or links a farmer using incoming partner hash.
    ALWAYS returns exactly {"status":"accepted"} with HTTP 200 for valid requests.
    """
    process_farmer_registration(
        db=db,
        partner_id=partner.partner_id,
        incoming_hash=payload.hash,
        gender=payload.gender,
        age_band=payload.age_band,
        county_code=payload.county_code,
        onboarded_at=payload.onboarded_at
    )
    db.commit()
    return StatusAcceptedResponse(status="accepted")


@router.post(":upload", response_model=UploadResponse)
async def upload_farmers_csv(
    request: Request,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Accepts multipart CSV or raw CSV (hash,gender,age_band,county_code,onboarded_at) for backfill.
    Executes identical idempotent logic per row.
    Returns {"rows_received": n, "rows_rejected": m}.
    """
    body = await request.body()
    content_type = request.headers.get("content-type", "")
    
    text = ""
    if "multipart/form-data" in content_type:
        msg = email.message_from_bytes(b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body)
        for part in msg.walk():
            filename = part.get_filename()
            ctype = part.get_content_type()
            if filename or ctype in ("text/csv", "application/vnd.ms-excel", "text/plain", "application/octet-stream"):
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8-sig", errors="replace")
                    break
        if not text and msg.is_multipart():
            for part in msg.get_payload():
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8-sig", errors="replace")
                    break
    else:
        text = body.decode("utf-8-sig", errors="replace")
    
    reader = csv.reader(io.StringIO(text))
    rows_received = 0
    rows_accepted = 0
    rows_rejected = 0
    
    seen_in_batch = set()
    first_row = True
    for row in reader:
        if not row or all(c.strip() == "" for c in row):
            continue
        
        # Check for header row
        if first_row and any(col.strip().lower() in ("hash", "gender", "age_band", "county_code") for col in row):
            first_row = False
            continue
        first_row = False
        
        rows_received += 1
        
        if len(row) < 4:
            rows_rejected += 1
            continue
        
        row_hash = row[0].strip()
        row_gender = row[1].strip().upper()
        row_age_band = row[2].strip()
        row_county = row[3].strip()
        row_onboarded_at = row[4].strip() if len(row) > 4 else None
        
        # Validate format
        if not HEX_64_REGEX.match(row_hash):
            rows_rejected += 1
            continue
        if row_gender not in VALID_GENDERS:
            rows_rejected += 1
            continue
        if row_age_band not in VALID_AGE_BANDS:
            rows_rejected += 1
            continue
        if not row_county:
            rows_rejected += 1
            continue
        
        dt = parse_iso_datetime(row_onboarded_at)
        
        # Check in-file repeat
        if row_hash in seen_in_batch:
            # Repeat inside same file: count as accepted resend
            rows_accepted += 1
            continue
        
        try:
            with db.begin_nested():
                process_farmer_registration(
                    db=db,
                    partner_id=partner.partner_id,
                    incoming_hash=row_hash,
                    gender=row_gender,
                    age_band=row_age_band,
                    county_code=row_county,
                    onboarded_at=dt
                )
                db.flush()
            seen_in_batch.add(row_hash)
            rows_accepted += 1
        except Exception:
            rows_rejected += 1
            continue

    db.commit()
    return UploadResponse(
        rows_received=rows_received,
        rows_accepted=rows_accepted,
        rows_rejected=rows_rejected
    )


@router.delete("/{incoming_hash}", response_model=StatusAcceptedResponse)
def withdraw_consent(
    incoming_hash: str,
    partner: Partner = Depends(authenticate_partner),
    db: Session = Depends(get_db)
):
    """
    Consent withdrawn by partner:
    - Mark this partner's link 'removed'
    - Delete the farmer if no active links remain across any partners
    - Always returns {"status":"accepted"} with HTTP 200
    """
    if not HEX_64_REGEX.match(incoming_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash format"
        )
    
    hash_key = rekey_hash(incoming_hash)
    farmer = db.query(Farmer).filter(Farmer.hash_key == hash_key).first()
    
    now = datetime.now(timezone.utc)
    if farmer:
        link = db.query(PartnerLink).filter(
            PartnerLink.farmer_id == farmer.id,
            PartnerLink.partner_id == partner.partner_id
        ).first()
        
        if link and link.status == "active":
            link.status = "removed"
            db.flush()
            
            # Check remaining active links across ALL partners
            active_links_count = db.query(PartnerLink).filter(
                PartnerLink.farmer_id == farmer.id,
                PartnerLink.status == "active"
            ).count()
            
            if active_links_count == 0:
                # No other partner has an active link to this farmer -> delete farmer
                db.delete(farmer)
            
            audit = AuditLog(
                action="consent_withdrawn",
                partner_id=partner.partner_id,
                farmer_id=None,
                at=now
            )
            db.add(audit)
            db.commit()
    
    return StatusAcceptedResponse(status="accepted")
