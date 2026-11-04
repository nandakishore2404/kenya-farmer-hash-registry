"""
VOPRF Independent Evaluator Router (RFC 9497 / 2-of-3 Shamir Split-Key)
- Evaluator node holding one secret share scalar s_i (custody isolated per institution)
- Provides /v1/evaluations, /v1/evaluator/public-key, and /v1/healthz
- Rolling 24-hour database-backed rate limiting quotas enforced independently at each party
- Returns evaluated points Zi = s_i * B with DLEQ proof against this party's Ki = s_i * G
- Strictly refuses startup if deprecated single-key EVALUATOR_SECRET_K is configured
"""

import os
import base64
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import OperationalError, DatabaseError

from app.config import settings, BURNED_SCALAR_INTS
from app.crypto.voprf import (
    VOPRFEngine,
    GroupElement,
    point_mul,
    GENERATOR_G,
    N_ORDER
)
from app.auth import authenticate_partner
from app.models import Partner, PartnerEvaluationQuota, AuditLog
from app.database import get_db, SessionLocal

import threading

_PARTNER_QUOTA_LOCKS: Dict[str, threading.Lock] = {}
_QUOTA_MUTEX = threading.Lock()

def get_partner_quota_lock(partner_id: str) -> threading.Lock:
    with _QUOTA_MUTEX:
        if partner_id not in _PARTNER_QUOTA_LOCKS:
            _PARTNER_QUOTA_LOCKS[partner_id] = threading.Lock()
        return _PARTNER_QUOTA_LOCKS[partner_id]

router = APIRouter(prefix="/v1", tags=["evaluator"])

def load_evaluator_share():
    """
    Loads active Evaluator key epoch and secret share scalar s_i from secure runtime environment.
    Refuses startup if single-key EVALUATOR_SECRET_K is present.
    Validates that:
      - Share s_i is present, exactly 64 hex, non-zero mod N_ORDER, not burned.
      - Ki derived from configured share matches party's entry in peer pubkeys.
    """
    if os.environ.get("EVALUATOR_SECRET_K") is not None:
        raise RuntimeError(
            "FATAL: EVALUATOR_SECRET_K is set. The system has migrated to a 2-of-3 split-key architecture. "
            "Single-key operation is strictly prohibited. Use EVALUATOR_SHARE_K instead."
        )

    key_id = getattr(settings, "EVALUATOR_KEY_ID", "ke-pilot-v4")
    party_id = getattr(settings, "EVALUATOR_PARTY_ID", "safic") or "safic"
    party_index = getattr(settings, "EVALUATOR_PARTY_INDEX", 1) or 1

    raw_share = getattr(settings, "EVALUATOR_SHARE_K", None) or os.environ.get("EVALUATOR_SHARE_K")
    if not raw_share:
        raise RuntimeError("FATAL: EVALUATOR_SHARE_K is not set or is empty. Evaluator cannot boot without its secret share.")

    raw_str = raw_share.get_secret_value() if hasattr(raw_share, "get_secret_value") else str(raw_share)
    clean_share = raw_str.strip()
    if not clean_share:
        raise RuntimeError("FATAL: EVALUATOR_SHARE_K is not set or is empty. Evaluator cannot boot without its secret share.")

    hex_share = clean_share[2:] if clean_share.startswith(("0x", "0X")) else clean_share
    if len(hex_share) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_share):
        raise ValueError("Evaluator configuration error: EVALUATOR_SHARE_K must be exactly 64 hexadecimal characters.")

    share_val = int(hex_share, 16) % N_ORDER
    if share_val == 0:
        raise RuntimeError("FATAL: EVALUATOR_SHARE_K cannot be zero modulo curve order.")
    if share_val in BURNED_SCALAR_INTS:
        raise RuntimeError("FATAL: EVALUATOR_SHARE_K matches a known burned scalar from public repository history.")

    pub_pt = point_mul(share_val, GENERATOR_G.pt)
    pub_elem = GroupElement(pub_pt)

    env = getattr(settings, "ENV", "production") or os.environ.get("ENV", "production")
    is_prod = str(env).strip().lower() == "production"

    # Peer public keys
    peer_str = getattr(settings, "EVALUATOR_PEER_PUBKEYS", None) or os.environ.get("EVALUATOR_PEER_PUBKEYS")
    if not peer_str or not peer_str.strip():
        if is_prod:
            raise RuntimeError("FATAL: EVALUATOR_PEER_PUBKEYS is required in production environment.")
        peer_str = (
            "BJ8m3hJug+Y0V7hR3rH84fa+5AIAQsVVaCaDTGfGTp56NzsOk2HZWOyrjGRbykUNlxVSqx24LC9mzf9T2FKm+zU=,"
            "BLsrheMvOj3EeWaaXImEgn7qplgNfOe0Ds6383CkKMvt67srGKCfMNJQ5aOe5+aagI0F9Yev8/gecI+7pbR1M4E=,"
            "BL0Geozqg73DQS/sOR+sFyzgpO4YYWS949WCcan5E1JWRbIE4qe/UZXT/gffBoaV22pkmUp4/9d6LqFWareOMXY="
        )
    peer_pubkeys = [k.strip() for k in peer_str.split(",") if k.strip()]
    if len(peer_pubkeys) != 3:
        raise RuntimeError(f"FATAL: EVALUATOR_PEER_PUBKEYS must contain exactly 3 keys, found {len(peer_pubkeys)}")

    # Verify Ki matches published key for this party index
    derived_b64 = base64.b64encode(pub_elem.to_bytes()).decode("utf-8")
    if derived_b64 != peer_pubkeys[party_index - 1]:
        raise RuntimeError(
            f"FATAL: Derived Ki for party index {party_index} does not match published peer public key '{peer_pubkeys[party_index - 1]}'"
        )

    # Aggregate public key K
    agg_b64 = getattr(settings, "EVALUATOR_AGGREGATE_PUB", None) or os.environ.get("EVALUATOR_AGGREGATE_PUB")
    if not agg_b64 or not agg_b64.strip():
        if is_prod:
            raise RuntimeError("FATAL: EVALUATOR_AGGREGATE_PUB is required in production environment.")
        agg_b64 = "BA1RzbWdkHqeSemHj3/wi6w6OOw0Nqxz9bf9xeos0UIKaO6Vv+vKZCZytQC460fvbMxzhljJ8OAlP+OYcWQwWhI="

    return key_id, party_id, party_index, share_val, pub_elem, agg_b64, peer_pubkeys

EVALUATOR_KEY_ID, EVALUATOR_PARTY_ID, EVALUATOR_PARTY_INDEX, EVALUATOR_SHARE_K, EVALUATOR_PUBLIC_KEY, EVALUATOR_AGGREGATE_PUB, EVALUATOR_PEER_PUBKEYS = load_evaluator_share()

class EvaluationRequest(BaseModel):
    pilot_id: str = Field(..., description="Pilot identifier, e.g. kenya-pilot")
    key_id: str = Field(..., description="Target Evaluator key version")
    request_id: str = Field(..., description="UUID for idempotency and replay protection")
    blinded_elements: List[str] = Field(..., description="Base64-encoded group elements B")

class EvaluatedElementResponse(BaseModel):
    key_id: str
    party_id: str
    party_index: int
    evaluated_elements: List[str]
    proofs: List[str]

@router.get("/healthz")
@router.get("/evaluator/healthz")
def get_healthz():
    """
    Evaluator Health Probe (Work package 3b / P3.4):
    Confirms node operational state, key epoch, and cryptographic integrity.
    Never exposes secret material.
    """
    return {
        "status": "healthy",
        "key_id": EVALUATOR_KEY_ID,
        "party_id": EVALUATOR_PARTY_ID,
        "party_index": EVALUATOR_PARTY_INDEX,
        "share_loaded": True,
        "public_key_verified": True
    }

@router.get("/evaluator/public-key")
def get_evaluator_public_key():
    """
    Returns aggregate public key K and all party public keys Ki (Work package 2 / Section 5.2).
    Unauthenticated by design.
    """
    party_names = ["safic", "operator", "independent"]
    parties = []
    for idx, name in enumerate(party_names, 1):
        parties.append({
            "party_id": name,
            "party_index": idx,
            "public_key": EVALUATOR_PEER_PUBKEYS[idx - 1]
        })

    return {
        "key_id": EVALUATOR_KEY_ID,
        "aggregate_public_key": EVALUATOR_AGGREGATE_PUB,
        "parties": parties
    }

@router.post("/evaluations", response_model=EvaluatedElementResponse)
def evaluate_blinded_batch(
    req: EvaluationRequest,
    partner: Partner = Depends(authenticate_partner),
    db: Optional[Session] = Depends(get_db)
):
    """
    RFC 9497 Split-Key Batch Evaluation (2-of-3 Shamir):
    Zi = s_i * B
    Computes DLEQ proof against party public key Ki = s_i * G.
    Evaluator never learns the cleartext phone numbers.
    Enforces independent 24h rolling database quota per party.
    """
    if req.key_id != EVALUATOR_KEY_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested key_id '{req.key_id}' does not match active Evaluator key '{EVALUATOR_KEY_ID}'"
        )

    if len(req.blinded_elements) == 0:
        raise HTTPException(status_code=400, detail="Empty evaluation request")
    if len(req.blinded_elements) > 500:
        raise HTTPException(status_code=400, detail="Batch size exceeds maximum limit of 500 elements")

    # Enforce database-backed 24-hour rolling evaluation quota
    now = datetime.now(timezone.utc)
    close_db = False
    if db is None or not isinstance(db, Session):
        db = SessionLocal()
        close_db = True

    try:
        partner_lock = get_partner_quota_lock(partner.partner_id)
        with partner_lock:
            # 1. Attempt row-level locking on Partner record for multi-worker Postgres deployments
            bind = db.get_bind() if hasattr(db, "get_bind") else getattr(db, "bind", None)
            is_sqlite = getattr(getattr(bind, "dialect", None), "name", "") == "sqlite"
            if not is_sqlite:
                try:
                    db.query(Partner).filter(Partner.partner_id == partner.partner_id).with_for_update().first()
                except (OperationalError, DatabaseError):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Quota lock contention, please retry."
                    )

            quota_window_hours = getattr(settings, "PARTNER_QUOTA_WINDOW_HOURS", 24)
            daily_limit = getattr(settings, "PARTNER_DAILY_QUOTA", 10000)
            cutoff = now - timedelta(hours=quota_window_hours)

            recent_count = db.query(
                func.coalesce(func.sum(PartnerEvaluationQuota.batch_size), 0)
            ).filter(
                PartnerEvaluationQuota.partner_id == partner.partner_id,
                PartnerEvaluationQuota.evaluated_at >= cutoff
            ).scalar() or 0

            batch_len = len(req.blinded_elements)
            if recent_count + batch_len > daily_limit:
                db.add(AuditLog(
                    action="partner_evaluation_quota_exceeded",
                    partner_id=partner.partner_id,
                    at=now
                ))
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Partner evaluation quota of {daily_limit} per {quota_window_hours}h exceeded. Anomaly tripwire engaged."
                )

            db.add(PartnerEvaluationQuota(
                partner_id=partner.partner_id,
                evaluated_at=now,
                batch_size=batch_len
            ))
            db.commit()
    finally:
        if close_db:
            db.close()

    evaluated_elements_b64 = []
    proofs_b64 = []

    for b_b64 in req.blinded_elements:
        try:
            raw_b = base64.b64decode(b_b64)
            B = GroupElement.from_bytes(raw_b)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid group element encoding, non-affine point, or point not on secp256k1 curve"
            )

        Zi, proof = VOPRFEngine.evaluate(EVALUATOR_SHARE_K, B, EVALUATOR_PUBLIC_KEY)
        evaluated_elements_b64.append(base64.b64encode(Zi.to_bytes()).decode("utf-8"))
        proofs_b64.append(base64.b64encode(proof).decode("utf-8"))

    return EvaluatedElementResponse(
        key_id=EVALUATOR_KEY_ID,
        party_id=EVALUATOR_PARTY_ID,
        party_index=EVALUATOR_PARTY_INDEX,
        evaluated_elements=evaluated_elements_b64,
        proofs=proofs_b64
    )
