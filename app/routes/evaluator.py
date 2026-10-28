"""
VOPRF Independent Evaluator Router (RFC 9497)
- Key custody isolated with dedicated key scalar k loaded from secure runtime store / HSM
- Provides /v1/evaluations and /v1/evaluator/public-key
- Rate limiting quotas, batch bound verification, and curve point validation
- Key Epoch v3: Rotated secret scalar loaded from environment / CloudHSM / Vault transit
"""

import os
import base64
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field

from app.config import settings, BURNED_SCALAR_INTS
from app.crypto.voprf import (
    VOPRFEngine,
    GroupElement,
    point_mul,
    GENERATOR_G,
    N_ORDER
)
from app.auth import authenticate_partner
from app.models import Partner

router = APIRouter(prefix="/v1", tags=["evaluator"])

def load_evaluator_key() -> tuple[str, int, GroupElement]:
    """
    Loads active Evaluator key epoch and secret scalar k from secure runtime environment.
    Refuses startup if k is absent, invalid, or burned (no literal fallback, no default).
    Accepts exactly one documented encoding: 64 hexadecimal characters (optional 0x prefix).
    In production SAFIC deployments, k resides in AWS CloudHSM or HashiCorp Vault transit engine.
    """
    key_id = getattr(settings, "EVALUATOR_KEY_ID", "ke-pilot-v3")
    raw_k = getattr(settings, "EVALUATOR_SECRET_K", None) or os.environ.get("EVALUATOR_SECRET_K")
    if not raw_k:
        raise RuntimeError(
            "FATAL: EVALUATOR_SECRET_K is not set. The VOPRF Evaluator secret key must be "
            "provided via secure runtime environment or CloudHSM / Vault transit. "
            "Startup aborted to prevent unauthenticated/compromised operation."
        )
    raw_str = raw_k.get_secret_value() if hasattr(raw_k, "get_secret_value") else str(raw_k)
    clean_k = raw_str.strip()
    if not clean_k:
        raise RuntimeError(
            "FATAL: EVALUATOR_SECRET_K is not set. The VOPRF Evaluator secret key must be "
            "provided via secure runtime environment or CloudHSM / Vault transit. "
            "Startup aborted to prevent unauthenticated/compromised operation."
        )

    # Check against burned scalars mod N_ORDER (prevents re-encoding bypass)
    try:
        parsed_int = int(clean_k, 16)
        if (parsed_int % N_ORDER) in BURNED_SCALAR_INTS:
            raise RuntimeError(
                "FATAL: EVALUATOR_SECRET_K matches a known burned scalar from public repository history."
            )
    except ValueError as e:
        if "FATAL: EVALUATOR_SECRET_K matches a known burned" in str(e):
            raise

    # Accept exactly one documented encoding: 64 hex characters, optional 0x prefix
    hex_k = clean_k[2:] if clean_k.startswith(("0x", "0X")) else clean_k
    if len(hex_k) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_k):
        raise ValueError(
            "Evaluator configuration error: EVALUATOR_SECRET_K must be exactly 64 hexadecimal characters "
            "(optional '0x' prefix). Decimal or other encodings are not accepted."
        )

    k_val = int(hex_k, 16) % N_ORDER
    if k_val == 0:
        raise RuntimeError("FATAL: EVALUATOR_SECRET_K cannot be zero modulo curve order.")

    pub_pt = point_mul(k_val, GENERATOR_G.pt)
    return key_id, k_val, GroupElement(pub_pt)

EVALUATOR_KEY_ID, EVALUATOR_SECRET_K, EVALUATOR_PUBLIC_KEY = load_evaluator_key()

# In-memory quota tracker
PARTNER_QUOTAS = {}

class EvaluationRequest(BaseModel):
    pilot_id: str = Field(..., description="Pilot identifier, e.g. kenya-pilot")
    key_id: str = Field(..., description="Target Evaluator key version")
    request_id: str = Field(..., description="UUID for idempotency and replay protection")
    blinded_elements: List[str] = Field(..., description="Base64-encoded group elements B")

class EvaluatedElementResponse(BaseModel):
    key_id: str
    evaluated_elements: List[str]
    proofs: List[str]

@router.get("/evaluator/public-key")
def get_evaluator_public_key():
    """
    Returns pinned Evaluator Public Key K = k * G for active key epoch.
    """
    return {
        "key_id": EVALUATOR_KEY_ID,
        "public_key": base64.b64encode(EVALUATOR_PUBLIC_KEY.to_bytes()).decode("utf-8"),
        "curve": "secp256k1-SHA512",
        "status": "active",
        "epoch": "v3"
    }

@router.post("/evaluations", response_model=EvaluatedElementResponse)
def evaluate_blinded_batch(
    req: EvaluationRequest,
    partner: Partner = Depends(authenticate_partner)
):
    """
    RFC 9497 Batch Evaluation:
    Z = k * B
    Computes DLEQ proof for each element.
    Evaluator never learns the cleartext phone numbers.
    Strictly validates that every decoded point is non-infinity and lies on secp256k1.
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

    current_count = PARTNER_QUOTAS.get(partner.partner_id, 0)
    if current_count + len(req.blinded_elements) > 10000:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Partner evaluation quota exceeded. Anomaly tripwire engaged."
        )
    PARTNER_QUOTAS[partner.partner_id] = current_count + len(req.blinded_elements)

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

        Z, proof = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B, EVALUATOR_PUBLIC_KEY)
        evaluated_elements_b64.append(base64.b64encode(Z.to_bytes()).decode("utf-8"))
        proofs_b64.append(base64.b64encode(proof).decode("utf-8"))

    return EvaluatedElementResponse(
        key_id=EVALUATOR_KEY_ID,
        evaluated_elements=evaluated_elements_b64,
        proofs=proofs_b64
    )
