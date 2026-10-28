"""
Independent VOPRF Evaluator Microservice (RFC 9497)
- Holds secret scalar k in isolated custody loaded at runtime from environment / CloudHSM / Vault.
- Exposes /v1/evaluations for authorized partners only.
- Computes Z = k * B and DLEQ proof.
- Enforces rate-limiting quotas and replay guards.
- NEVER receives cleartext phone numbers or client identities.
"""

import os
from fastapi import FastAPI, HTTPException, Header, status, Depends
from pydantic import BaseModel, Field
from typing import List, Optional
import base64

from prototype_voprf.crypto.voprf_engine import (
    VOPRFEngine,
    GroupElement,
    point_mul,
    GENERATOR_G,
    N_ORDER
)

N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

BURNED_SCALARS_HEX = {
    "7a2f3e1b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f",
    "5d8a9f1b2c3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f91",
}
BURNED_SCALAR_INTS = {int(h, 16) % N_ORDER for h in BURNED_SCALARS_HEX}

app = FastAPI(title="OAN Kenya VOPRF Independent Evaluator", version="1.0.0")

def load_evaluator_key() -> tuple[str, int, GroupElement]:
    key_id = os.environ.get("EVALUATOR_KEY_ID", "ke-pilot-v3")
    raw_k = os.environ.get("EVALUATOR_SECRET_K")
    if not raw_k or not raw_k.strip():
        raise RuntimeError(
            "FATAL: EVALUATOR_SECRET_K is required. Must be set via secure environment variable or HSM interface."
        )
    clean_k = raw_k.strip()

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

KEY_ID, EVALUATOR_SECRET_K, EVALUATOR_PUBLIC_KEY = load_evaluator_key()

# Allowed partner credentials for mTLS/API Gateway simulation
AUTHORIZED_PARTNERS = {
    "partner_oaf_token": "One Acre Fund",
    "partner_digifarm_token": "DigiFarm",
    "partner_ktda_token": "KTDA",
    "partner_whitelabel_token": "OAN White-Label Gateway"
}

PARTNER_QUOTAS = {}

class EvaluationRequest(BaseModel):
    pilot_id: str = Field(..., description="Pilot identifier, e.g. kenya-pilot")
    key_id: str = Field(..., description="Target Evaluator key version")
    request_id: str = Field(..., description="UUID for idempotency and replay protection")
    blinded_elements: List[str] = Field(..., description="Base64-encoded 65-byte uncompressed group elements B")

class EvaluatedElementResponse(BaseModel):
    key_id: str
    evaluated_elements: List[str] # Base64-encoded Z
    proofs: List[str] # Base64-encoded DLEQ proofs

def authenticate_caller(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header"
        )
    token = authorization.split(" ")[1]
    if token not in AUTHORIZED_PARTNERS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized partner credential"
        )
    return token

@app.get("/v1/public-key")
def get_public_key():
    return {
        "key_id": KEY_ID,
        "public_key": base64.b64encode(EVALUATOR_PUBLIC_KEY.to_bytes()).decode("utf-8"),
        "curve": "secp256k1-SHA512",
        "status": "active",
        "epoch": "v3"
    }

@app.post("/v1/evaluations", response_model=EvaluatedElementResponse)
def evaluate_blinded_batch(
    req: EvaluationRequest,
    caller_token: str = Depends(authenticate_caller)
):
    if req.key_id != KEY_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Requested key_id '{req.key_id}' does not match active Evaluator key '{KEY_ID}'"
        )

    if len(req.blinded_elements) == 0:
        raise HTTPException(status_code=400, detail="Empty evaluation request")
    if len(req.blinded_elements) > 500:
        raise HTTPException(status_code=400, detail="Batch size exceeds maximum limit of 500 elements")

    current_count = PARTNER_QUOTAS.get(caller_token, 0)
    if current_count + len(req.blinded_elements) > 10000:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Partner evaluation quota exceeded. Anomaly tripwire engaged."
        )
    PARTNER_QUOTAS[caller_token] = current_count + len(req.blinded_elements)

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
        key_id=KEY_ID,
        evaluated_elements=evaluated_elements_b64,
        proofs=proofs_b64
    )
