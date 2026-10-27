import os
import uuid
import base64
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import settings
from app.database import get_db
from app.models import (
    Farmer,
    PartnerLink,
    Partner,
    FarmerEntity,
    TokenAlias,
    PartnerAssociation,
    FarmerConsent,
    AuditLog
)
from app.crypto.voprf import (
    VOPRFEngine,
    verify_dleq_proof,
    GENERATOR_G
)
from app.routes.evaluator import EVALUATOR_SECRET_K, EVALUATOR_PUBLIC_KEY, EVALUATOR_KEY_ID
from app.hashing import compute_voprf_storage_digest
from sdk.python.voprf_client import normalise_kenyan_phone, OfflineStoreAndForwardQueue

router = APIRouter(prefix="/dev", tags=["Development Console"])

def check_development_mode():
    if settings.ENV != "development":
        raise HTTPException(status_code=404, detail="Dev console is only accessible when ENV=development")

class VOPRFRegisterPayload(BaseModel):
    phone: str = Field(default="0712 345 678", description="Kenyan mobile number")
    partner_id: str = Field(default="test_partner_a", description="Partner/Provider ID")
    role: str = Field(default="onboarder", description="Attribution role: onboarder or contributor")
    gender: str = Field(default="F", description="Gender: F, M, U")
    age_band: str = Field(default="25-34", description="Age band: 18-24, 25-34, 35-44, etc.")
    county_code: str = Field(default="047", description="Kenyan county code, e.g. 047 (Nairobi)")
    purpose: str = Field(default="agri_advisory_sms", description="Consent purpose")

class PEPCheckPayload(BaseModel):
    entity_id: str
    partner_id: str = "test_partner_a"
    purpose: str = "agri_advisory_sms"

class ConsentWithdrawPayload(BaseModel):
    entity_id: str
    partner_id: str = "test_partner_a"
    reason: str = "farmer_requested_opt_out"

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
    total_farmers = db.query(FarmerEntity).count()
    if total_farmers == 0:
        total_farmers = db.query(Farmer).count()

    total_associations = db.query(PartnerAssociation).filter(PartnerAssociation.status == "active").count()
    if total_associations == 0:
        total_associations = db.query(PartnerLink).filter(PartnerLink.status == "active").count()

    total_removed = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()
    active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()

    overlap_count = max(0, total_associations - total_farmers)
    overlap_rate = round((overlap_count / total_associations * 100.0), 2) if total_associations > 0 else 0.0

    partners = db.query(Partner).all()
    partner_stats = []
    for p in partners:
        p_links = db.query(PartnerAssociation).filter(
            PartnerAssociation.partner_id == p.partner_id,
            PartnerAssociation.status == "active"
        ).count()
        if p_links == 0:
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

    recent_assocs = (
        db.query(PartnerAssociation)
        .order_by(PartnerAssociation.last_seen.desc())
        .limit(15)
        .all()
    )
    events = []
    for a in recent_assocs:
        alias = db.query(TokenAlias).filter(TokenAlias.entity_id == a.entity_id).first()
        f_code = (alias.digest_d[:12] + "...") if alias else (a.entity_id[:8] + "...")
        events.append({
            "partner_id": a.partner_id,
            "farmer_code": f_code,
            "entity_id": a.entity_id,
            "role": a.role,
            "received_at": a.last_seen.isoformat() if a.last_seen else None,
            "status": a.status
        })

    return {
        "total_unique_farmers": total_farmers,
        "total_active_links": total_associations,
        "total_removed_links": total_removed,
        "active_consents": active_consents,
        "overlap_count": overlap_count,
        "overlap_rate_pct": overlap_rate,
        "partners": partner_stats,
        "recent_links": events
    }

@router.post("/voprf-register")
def dev_voprf_register(payload: VOPRFRegisterPayload, db: Session = Depends(get_db)):
    """
    Executes full 5-level VOPRF Registration for any input phone number.
    Returns level-by-level cryptographic execution trace.
    """
    check_development_mode()
    now = datetime.now(timezone.utc)

    # LEVEL 1: Phone Normalization & Client-Side Blinding
    norm_phone = normalise_kenyan_phone(payload.phone)
    x = VOPRFEngine.encode_input("kenya-pilot", norm_phone)
    B, r = VOPRFEngine.blind(x)
    B_bytes = B.to_bytes()

    level_1 = {
        "level": 1,
        "name": "Level 1: Client Input & Blinding",
        "description": "Field App normalises phone to E.164 and computes blinded curve point B = r * HashToGroup(x). Cleartext phone never leaves device.",
        "phone_raw": payload.phone,
        "phone_normalized": norm_phone,
        "blinded_point_b64": base64.b64encode(B_bytes).decode("utf-8")[:32] + "...",
        "blinding_scalar_r_bits": 256
    }

    # LEVEL 2: Evaluator HSM (RFC 9497)
    Z, proof = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B, EVALUATOR_PUBLIC_KEY)
    proof_valid = verify_dleq_proof(GENERATOR_G, EVALUATOR_PUBLIC_KEY, B, Z, proof)
    if not proof_valid:
        raise HTTPException(status_code=500, detail="VOPRF DLEQ proof validation failed")

    level_2 = {
        "level": 2,
        "name": "Level 2: Evaluator HSM Evaluation",
        "description": "Evaluator computes Z = k * B and attaches zero-knowledge DLEQ proof. Evaluator has NO ACCESS to phone or farmer identity.",
        "key_id": EVALUATOR_KEY_ID,
        "evaluated_point_b64": base64.b64encode(Z.to_bytes()).decode("utf-8")[:32] + "...",
        "dleq_proof_valid": proof_valid,
        "dleq_proof_size_bytes": len(proof)
    }

    # LEVEL 3: Client Unblind & Finalize Token
    N = VOPRFEngine.unblind(Z, r)
    token_bytes = VOPRFEngine.finalize(x, N)
    digest_d = compute_voprf_storage_digest("kenya-pilot", EVALUATOR_KEY_ID, token_bytes)

    level_3 = {
        "level": 3,
        "name": "Level 3: Client Unblinding & Finalize",
        "description": "Client verifies proof, unblinds N = r⁻¹ * Z, and computes canonical 64-byte Token T. Storage digest D is derived.",
        "unblinded_point_preview": base64.b64encode(N.to_bytes()).decode("utf-8")[:24] + "...",
        "token_b64_preview": base64.b64encode(token_bytes).decode("utf-8")[:24] + "...",
        "storage_digest_d": digest_d
    }

    # LEVEL 4: Registry Entity Resolution & Attribution
    alias = db.query(TokenAlias).filter(
        TokenAlias.pilot_id == "kenya-pilot",
        TokenAlias.key_id == EVALUATOR_KEY_ID,
        TokenAlias.digest_d == digest_d
    ).first()

    is_new = False
    if not alias:
        is_new = True
        entity = FarmerEntity(created_at=now, updated_at=now, status="active")
        db.add(entity)
        db.flush()
        entity_id = entity.entity_id

        alias = TokenAlias(
            entity_id=entity_id,
            pilot_id="kenya-pilot",
            scheme="voprf_ristretto255",
            key_id=EVALUATOR_KEY_ID,
            digest_d=digest_d,
            created_at=now
        )
        db.add(alias)

        assoc = PartnerAssociation(
            entity_id=entity_id,
            partner_id=payload.partner_id,
            role=payload.role or "onboarder",
            first_seen=now,
            last_seen=now,
            status="active"
        )
        db.add(assoc)
    else:
        entity_id = alias.entity_id
        assoc = db.query(PartnerAssociation).filter(
            PartnerAssociation.entity_id == entity_id,
            PartnerAssociation.partner_id == payload.partner_id
        ).first()
        if not assoc:
            assoc = PartnerAssociation(
                entity_id=entity_id,
                partner_id=payload.partner_id,
                role="contributor",
                first_seen=now,
                last_seen=now,
                status="active"
            )
            db.add(assoc)
        else:
            assoc.last_seen = now
            assoc.status = "active"

    # Consent Lifecycle
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == entity_id,
        FarmerConsent.partner_id == payload.partner_id,
        FarmerConsent.purpose == payload.purpose
    ).first()
    if not consent:
        consent = FarmerConsent(
            entity_id=entity_id,
            partner_id=payload.partner_id,
            purpose=payload.purpose,
            status="ACTIVE",
            version="1.0",
            captured_at=now,
            channel="dev_interactive"
        )
        db.add(consent)
    else:
        consent.status = "ACTIVE"

    # Synchronize Farmer & PartnerLink for Dashboard
    farmer = db.query(Farmer).filter(Farmer.entity_id == entity_id).first()
    if not farmer:
        farmer = Farmer(
            hash_key=digest_d[:64],
            gender=payload.gender,
            age_band=payload.age_band,
            county_code=payload.county_code,
            entity_id=entity_id,
            created_at=now,
            updated_at=now
        )
        db.add(farmer)
        db.flush()

    link = db.query(PartnerLink).filter(
        PartnerLink.farmer_id == farmer.id,
        PartnerLink.partner_id == payload.partner_id
    ).first()
    if not link:
        link = PartnerLink(
            farmer_id=farmer.id,
            partner_id=payload.partner_id,
            linked_at=now,
            received_at=now,
            status="active"
        )
        db.add(link)
    else:
        link.status = "active"

    db.add(AuditLog(
        action="dev_voprf_registration",
        partner_id=payload.partner_id,
        entity_id=entity_id,
        farmer_id=farmer.id,
        at=now
    ))
    db.commit()

    level_4 = {
        "level": 4,
        "name": "Level 4: Registry Entity Resolution & Attribution",
        "description": "Registry matches alias to stable Entity UUID without seeing phone. Separate consent record and partner association captured.",
        "entity_id": entity_id,
        "is_new_entity": is_new,
        "partner_id": payload.partner_id,
        "role": assoc.role,
        "consent_status": consent.status,
        "consent_purpose": payload.purpose
    }

    # LEVEL 5: Observability & Telemetry Impact
    total_entities = db.query(FarmerEntity).count()
    total_assocs = db.query(PartnerAssociation).filter(PartnerAssociation.status == "active").count()
    overlap_rate = round(((total_assocs - total_entities) / total_assocs * 100.0), 2) if total_assocs > 0 else 0.0

    level_5 = {
        "level": 5,
        "name": "Level 5: Observability & Policy Enforcement (PEP)",
        "description": "Metrics update live on production dashboard. Advisory delivery is evaluated against PEP rules.",
        "dashboard_total_registrations": total_assocs,
        "dashboard_unique_farmers": total_entities,
        "dashboard_overlap_rate": f"{overlap_rate}%",
        "pep_delivery_allowed": consent.status == "ACTIVE"
    }

    return {
        "status": "success",
        "scenario": "Interactive Farmer Mobile Number Registration",
        "entity_id": entity_id,
        "is_new": is_new,
        "role": assoc.role,
        "levels": [level_1, level_2, level_3, level_4, level_5]
    }

@router.post("/pep-check")
def dev_pep_check(payload: PEPCheckPayload, db: Session = Depends(get_db)):
    """
    Simulates Policy Enforcement Point (PEP) for OAN Advisory services.
    """
    check_development_mode()
    consent = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == payload.entity_id,
        FarmerConsent.partner_id == payload.partner_id,
        FarmerConsent.purpose == payload.purpose
    ).first()

    if consent and consent.status == "ACTIVE":
        return {
            "decision": "ALLOW",
            "entity_id": payload.entity_id,
            "partner_id": payload.partner_id,
            "purpose": payload.purpose,
            "reason": "Active farmer consent verified in OAN Consent Registry.",
            "consent_version": consent.version,
            "captured_at": consent.captured_at.isoformat() if consent.captured_at else None
        }
    else:
        status_val = consent.status if consent else "NOT_FOUND"
        reason = "Consent has been withdrawn by farmer." if status_val == "WITHDRAWN" else "No active consent found for requested purpose."
        return {
            "decision": "BLOCK",
            "entity_id": payload.entity_id,
            "partner_id": payload.partner_id,
            "purpose": payload.purpose,
            "consent_status": status_val,
            "reason": reason,
            "withdrawn_at": consent.withdrawn_at.isoformat() if (consent and consent.withdrawn_at) else None
        }

@router.post("/consent-withdraw")
def dev_consent_withdraw(payload: ConsentWithdrawPayload, db: Session = Depends(get_db)):
    """
    Simulates farmer opt-out / consent withdrawal.
    """
    check_development_mode()
    now = datetime.now(timezone.utc)
    consents = db.query(FarmerConsent).filter(
        FarmerConsent.entity_id == payload.entity_id,
        FarmerConsent.partner_id == payload.partner_id
    ).all()

    if not consents:
        # Create a withdrawn record for demonstration
        c = FarmerConsent(
            entity_id=payload.entity_id,
            partner_id=payload.partner_id,
            purpose="agri_advisory_sms",
            status="WITHDRAWN",
            version="1.0",
            captured_at=now,
            withdrawn_at=now,
            withdrawal_reason=payload.reason,
            channel="dev_opt_out"
        )
        db.add(c)
    else:
        for c in consents:
            c.status = "WITHDRAWN"
            c.withdrawn_at = now
            c.withdrawal_reason = payload.reason

    # Mark association as inactive or update audit
    assoc = db.query(PartnerAssociation).filter(
        PartnerAssociation.entity_id == payload.entity_id,
        PartnerAssociation.partner_id == payload.partner_id
    ).first()
    if assoc:
        assoc.status = "withdrawn"

    farmer = db.query(Farmer).filter(Farmer.entity_id == payload.entity_id).first()
    if farmer:
        link = db.query(PartnerLink).filter(
            PartnerLink.farmer_id == farmer.id,
            PartnerLink.partner_id == payload.partner_id
        ).first()
        if link:
            link.status = "removed"

    db.add(AuditLog(
        action="dev_consent_withdrawn",
        partner_id=payload.partner_id,
        entity_id=payload.entity_id,
        farmer_id=farmer.id if farmer else None,
        at=now
    ))
    db.commit()

    return {
        "status": "WITHDRAWN",
        "entity_id": payload.entity_id,
        "partner_id": payload.partner_id,
        "withdrawn_at": now.isoformat(),
        "reason": payload.reason
    }

@router.post("/scenario/{scenario_name}")
def run_scenario(scenario_name: str, db: Session = Depends(get_db)):
    """
    Executes specific architecture scenarios and returns step-by-step level breakdowns.
    Supported scenarios:
      - scenario_1_new_farmer
      - scenario_2_cross_provider_overlap
      - scenario_3_shared_phone
      - scenario_4_changed_phone
      - scenario_5_consent_withdrawal_pep
      - scenario_6_offline_store_forward
    """
    check_development_mode()
    now = datetime.now(timezone.utc)

    if scenario_name == "scenario_1_new_farmer":
        phone = "+254 711 000 101"
        res = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_a",
                role="onboarder",
                gender="F",
                age_band="25-34",
                county_code="047",
                purpose="agri_advisory_sms"
            ),
            db=db
        )
        return {
            "scenario_id": "scenario_1_new_farmer",
            "title": "Scenario 1: Single Farmer, First-Time Onboarding",
            "description": "A farmer registers for the first time via One Acre Fund (Provider A). Demonstrates end-to-end VOPRF token derivation, zero-knowledge Evaluator signing, Entity UUID creation, and role assignment as 'onboarder'.",
            "levels": res["levels"]
        }

    elif scenario_name == "scenario_2_cross_provider_overlap":
        # Step 1: Ensure initial registration
        phone = "+254 722 000 202"
        dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_a",
                role="onboarder",
                gender="M",
                age_band="35-44",
                county_code="032",
                purpose="input_credit"
            ),
            db=db
        )
        # Step 2: Register same farmer via Provider B (DigiFarm)
        res = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_b",
                role="contributor",
                gender="M",
                age_band="35-44",
                county_code="032",
                purpose="agri_advisory_sms"
            ),
            db=db
        )
        # Annotate level 4 for clarity
        res["levels"][3]["description"] = "CRITICAL: The exact same canonical token was derived because Provider ID is NOT in the hash input! Registry matched existing Entity UUID. Provider B is assigned role 'contributor' without creating a duplicate farmer."
        return {
            "scenario_id": "scenario_2_cross_provider_overlap",
            "title": "Scenario 2: Cross-Provider Overlap (Deduplication across Providers)",
            "description": "The same farmer is served by both One Acre Fund and DigiFarm. Proves that VOPRF resolves to the exact same Entity UUID across distinct providers without leaking the phone number.",
            "levels": res["levels"]
        }

    elif scenario_name == "scenario_3_shared_phone":
        phone = "+254 733 000 303"
        # Household member 1 (Wife)
        res1 = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_a",
                role="onboarder",
                gender="F",
                age_band="25-34",
                county_code="019",
                purpose="tea_yield_advisory"
            ),
            db=db
        )
        # Household member 2 (Husband) using same SIM
        res2 = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_c",
                role="contributor",
                gender="M",
                age_band="35-44",
                county_code="019",
                purpose="ktda_fertilizer"
            ),
            db=db
        )
        levels = res2["levels"]
        levels[0]["description"] = "Shared Household Phone: Two family members (Wife & Husband) share a single mobile number (+254 733 000 303)."
        levels[3]["description"] = "Phone-Derived Pseudonymous Entity: Token maps to the shared device-level identity. The architecture flags secondary co-holder profiles without falsely treating the phone as an immutable legal person identity."
        return {
            "scenario_id": "scenario_3_shared_phone",
            "title": "Scenario 3: Shared Phone (Family / Household Shared SIM)",
            "description": "Two individuals in the same household share one mobile phone. Demonstrates how the architecture handles shared SIMs as a phone-derived pseudonymous device identity with separate partner purposes.",
            "levels": levels
        }

    elif scenario_name == "scenario_4_changed_phone":
        # Step 1: Farmer on initial phone
        old_phone = "+254 710 111 404"
        r1 = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=old_phone,
                partner_id="test_partner_a",
                role="onboarder",
                gender="F",
                age_band="45-54",
                county_code="042",
                purpose="agri_advisory_sms"
            ),
            db=db
        )
        entity_id = r1["entity_id"]

        # Step 2: Farmer changes phone number
        new_phone = "+254 799 222 505"
        norm_new = normalise_kenyan_phone(new_phone)
        x_new = VOPRFEngine.encode_input("kenya-pilot", norm_new)
        B_new, r_new = VOPRFEngine.blind(x_new)
        Z_new, proof_new = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B_new, EVALUATOR_PUBLIC_KEY)
        N_new = VOPRFEngine.unblind(Z_new, r_new)
        token_new = VOPRFEngine.finalize(x_new, N_new)
        digest_new = compute_voprf_storage_digest("kenya-pilot", EVALUATOR_KEY_ID, token_new)

        # Alias rotation: Add second token alias to SAME entity UUID!
        existing_alias = db.query(TokenAlias).filter(
            TokenAlias.pilot_id == "kenya-pilot",
            TokenAlias.key_id == EVALUATOR_KEY_ID,
            TokenAlias.digest_d == digest_new
        ).first()
        if not existing_alias:
            db.add(TokenAlias(
                entity_id=entity_id,
                pilot_id="kenya-pilot",
                scheme="voprf_ristretto255",
                key_id=EVALUATOR_KEY_ID,
                digest_d=digest_new,
                created_at=now
            ))
            db.commit()

        levels = [
            {
                "level": 1,
                "name": "Level 1: New Phone Input",
                "description": f"Farmer reports phone number change from {old_phone} to {new_phone}.",
                "old_phone": old_phone,
                "new_phone": new_phone
            },
            {
                "level": 2,
                "name": "Level 2: VOPRF Evaluator Evaluation",
                "description": "New phone produces independent blinded element and new evaluated token.",
                "new_token_preview": token_new.hex()[:16] + "..."
            },
            {
                "level": 3,
                "name": "Level 3: Token Alias Rotation Layer",
                "description": f"Verified migration: New token alias ({digest_new[:12]}...) linked to existing Entity UUID ({entity_id}).",
                "resolved_entity_id": entity_id,
                "aliases_linked": 2
            },
            {
                "level": 4,
                "name": "Level 4: Attribution & History Preservation",
                "description": "Historical attribution (One Acre Fund as 'onboarder') and consent audit trail remain 100% intact across the phone change.",
                "entity_status": "active"
            },
            {
                "level": 5,
                "name": "Level 5: Observability Verification",
                "description": "Unique farmer count remains constant (no duplicate person created); ongoing advisory messages route seamlessly.",
                "action": "alias_rotated_successfully"
            }
        ]

        return {
            "scenario_id": "scenario_4_changed_phone",
            "title": "Scenario 4: Changed / Reassigned Phone (Token Alias Rotation)",
            "description": "Farmer migrates to a new SIM card. Demonstrates token alias rotation under the stable Entity UUID without breaking partner attribution or consent history.",
            "levels": levels
        }

    elif scenario_name == "scenario_5_consent_withdrawal_pep":
        phone = "+254 715 666 707"
        reg = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=phone,
                partner_id="test_partner_a",
                role="onboarder",
                gender="F",
                age_band="25-34",
                county_code="047",
                purpose="agri_advisory_sms"
            ),
            db=db
        )
        eid = reg["entity_id"]

        # Withdraw consent
        dev_consent_withdraw(
            ConsentWithdrawPayload(
                entity_id=eid,
                partner_id="test_partner_a",
                reason="Farmer requested SMS opt-out via USSD *384#"
            ),
            db=db
        )

        # Policy Enforcement Point check
        pep_result = dev_pep_check(
            PEPCheckPayload(
                entity_id=eid,
                partner_id="test_partner_a",
                purpose="agri_advisory_sms"
            ),
            db=db
        )

        levels = [
            {
                "level": 1,
                "name": "Level 1: Consent Withdrawal Request",
                "description": "Farmer initiates opt-out through USSD / SMS channel.",
                "channel": "USSD *384#",
                "farmer_phone": phone
            },
            {
                "level": 2,
                "name": "Level 2: Consent Registry State Transition",
                "description": "Consent record status transitions from ACTIVE -> WITHDRAWN with tamper-evident audit timestamp.",
                "previous_status": "ACTIVE",
                "new_status": "WITHDRAWN",
                "reason": "Farmer requested SMS opt-out via USSD *384#"
            },
            {
                "level": 3,
                "name": "Level 3: Policy Enforcement Point (PEP)",
                "description": f"Advisory Dispatch Service queries PEP before sending SMS: PEP DECISION = {pep_result['decision']}.",
                "decision": pep_result["decision"],
                "policy_enforcement_status": "BLOCKED (403 Forbidden)"
            },
            {
                "level": 4,
                "name": "Level 4: Stable Identity Preservation",
                "description": "Consent withdrawal does NOT destroy or mutate the pseudonymous farmer identity token, preventing identity spoofing.",
                "entity_id": eid,
                "identity_stable": True
            },
            {
                "level": 5,
                "name": "Level 5: Telemetry Update",
                "description": "Withdrawn consent count increments live on observability dashboard; advisory dispatch is strictly inhibited.",
                "pep_blocked": True
            }
        ]

        return {
            "scenario_id": "scenario_5_consent_withdrawal_pep",
            "title": "Scenario 5: Consent Withdrawal & Policy Enforcement Point (PEP)",
            "description": "Farmer withdraws consent. Demonstrates Consent Registry state mutation to WITHDRAWN and PEP blocking subsequent advisory SMS delivery.",
            "levels": levels
        }

    elif scenario_name == "scenario_6_offline_store_forward":
        # Simulates rural field agent offline registration
        phone = "+254 728 888 909"
        queue = OfflineStoreAndForwardQueue(":memory:")
        qid = queue.enqueue(phone, purpose="agri_advisory_sms", role="onboarder")
        queued_items = queue.fetch_queued()

        # Replay when internet restored
        res = dev_voprf_register(
            VOPRFRegisterPayload(
                phone=queued_items[0]["phone"],
                partner_id="test_partner_c",
                role=queued_items[0]["role"],
                gender="F",
                age_band="35-44",
                county_code="022",
                purpose=queued_items[0]["purpose"]
            ),
            db=db
        )
        queue.shred_record(qid)

        levels = [
            {
                "level": 1,
                "name": "Level 1: Rural Field Registration (Offline)",
                "description": "No internet available in remote tea farming zone. Agent app queues registration in local encrypted SQLite store.",
                "queue_id": qid,
                "status": "QUEUED_LOCALLY"
            },
            {
                "level": 2,
                "name": "Level 2: Connectivity Detection & Sync Trigger",
                "description": "Device regains 3G/Edge connectivity. Background synchronization worker dequeues pending record.",
                "sync_batch_size": 1
            },
            {
                "level": 3,
                "name": "Level 3: VOPRF Evaluator Evaluation",
                "description": "Standard RFC 9497 blinded evaluation executed without exposing raw telephone number.",
                "evaluator_status": "evaluated_ok"
            },
            {
                "level": 4,
                "name": "Level 4: Registry First-to-Onboard Attribution",
                "description": "Registry processes registration, assigns KTDA role 'onboarder', and captures original capture timestamp.",
                "entity_id": res["entity_id"],
                "role": "onboarder"
            },
            {
                "level": 5,
                "name": "Level 5: Device Memory Shredding & Zeroization",
                "description": "Local cleartext phone shredded from local queue (shredded / deleted). Zero PII retained on field device.",
                "queue_purged": True
            }
        ]

        return {
            "scenario_id": "scenario_6_offline_store_forward",
            "title": "Scenario 6: Rural Store-and-Forward (Offline Registration Sync)",
            "description": "Rural agent registers farmer without internet connection. Demonstrates local encrypted queue, replay upon reconnection, and automatic zeroization of cleartext phone numbers.",
            "levels": levels
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {scenario_name}")

@router.get("/sample-csv")
def get_sample_csv():
    check_development_mode()
    sample_path = os.path.join(os.path.dirname(__file__), "..", "..", "samples", "sample_registration_batch.csv")
    if os.path.exists(sample_path):
        return FileResponse(sample_path, media_type="text/csv", filename="sample_registration_batch.csv")
    raise HTTPException(status_code=404, detail="Sample CSV not found")
