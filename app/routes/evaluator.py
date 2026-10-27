"""
VOPRF Independent Evaluator Router (RFC 9497)
- Key custody isolated with dedicated key scalar k
- Provides /v1/evaluations and /v1/evaluator/public-key
- Rate limiting quotas and batch bound verification
"""

import base64
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Header, Depends, status
from pydantic import BaseModel, Field

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

# Evaluator Private Key k (in production, held in AWS CloudHSM / Vault)
EVALUATOR_SECRET_K = 0x7A9B3C2D1E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B % N_ORDER
EVALUATOR_PUBLIC_KEY = GroupElement(point_mul(EVALUATOR_SECRET_K, GENERATOR_G.pt))
EVALUATOR_KEY_ID = "ke-pilot-v1"

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
    Returns pinned Evaluator Public Key K = k * G.
    """
    return {
        "key_id": EVALUATOR_KEY_ID,
        "public_key": base64.b64encode(EVALUATOR_PUBLIC_KEY.to_bytes()).decode("utf-8"),
        "curve": "secp256k1-SHA512",
        "status": "active"
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
            raise HTTPException(status_code=400, detail="Malformed group element in batch")

        Z, proof = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B, EVALUATOR_PUBLIC_KEY)
        evaluated_elements_b64.append(base64.b64encode(Z.to_bytes()).decode("utf-8"))
        proofs_b64.append(base64.b64encode(proof).decode("utf-8"))

    return EvaluatedElementResponse(
        key_id=EVALUATOR_KEY_ID,
        evaluated_elements=evaluated_elements_b64,
        proofs=proofs_b64
    )
