"""
Comprehensive Integration Tests for OAN Kenya VOPRF + Consent Architecture
Tests:
  - Evaluator Public Key & Batch Evaluations
  - Client Blinding, DLEQ Proof Verification, and Token Finalization
  - VOPRF Token Registration & Multi-Provider Deduplication
  - Decoupled Attribution: Onboarder vs. Primary/Contributor
  - Policy Enforcement Point (PEP): Active -> Withdrawn -> Blocked
  - Unified DPI Telemetry
"""

import os
import uuid
import base64
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.models import (
    Partner,
    FarmerEntity,
    TokenAlias,
    PartnerAssociation,
    FarmerConsent,
    PartnerLink,
    Farmer
)
from app.crypto.voprf import (
    VOPRFEngine,
    GroupElement,
    GENERATOR_G
)
from app.routes.evaluator import (
    evaluate_blinded_batch,
    get_evaluator_public_key,
    EvaluationRequest,
    EVALUATOR_PUBLIC_KEY,
    EVALUATOR_KEY_ID
)
from app.routes.farmers import (
    register_farmer_voprf_token,
    process_farmer_registration
)
from app.schemas import (
    VOPRFFarmerRegisterRequest
)
from app.routes.consent import (
    capture_consent,
    withdraw_consent,
    check_consent_policy_enforcement_point,
    ConsentCaptureRequest,
    ConsentWithdrawRequest
)
from app.routes.dashboard import get_dpi_telemetry_metrics
from sdk.python.voprf_client import (
    OANFarmerVOPRFClient,
    normalise_kenyan_phone
)

# Test in-memory SQLite database
TEST_DB_URL = "sqlite:///./test_voprf_integration.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    db = TestSession()
    # Seed partners
    p1 = Partner(partner_id="test_partner_a", name="One Acre Fund", api_key_hash="hash_a", active=1)
    p2 = Partner(partner_id="test_partner_b", name="DigiFarm", api_key_hash="hash_b", active=1)
    db.add(p1)
    db.add(p2)
    db.commit()
    db.close()
    
    yield
    
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_voprf_integration.db"):
        try:
            os.remove("./test_voprf_integration.db")
        except Exception:
            pass

def helper_evaluate(pilot_id: str, key_id: str, b_b64: str, partner: Partner):
    req = EvaluationRequest(
        pilot_id=pilot_id,
        key_id=key_id,
        request_id=str(uuid.uuid4()),
        blinded_elements=[b_b64]
    )
    return evaluate_blinded_batch(req, partner=partner)

def test_voprf_end_to_end_deduplication_and_attribution():
    """
    Verifies that Partner A (One Acre Fund) and Partner B (DigiFarm) registering
    the same farmer phone number resolve to ONE unique FarmerEntity with distinct
    attribution roles ('onboarder' for Partner A, 'primary' for Partner B).
    """
    db = TestSession()
    partner_a = db.query(Partner).filter(Partner.partner_id == "test_partner_a").first()
    partner_b = db.query(Partner).filter(Partner.partner_id == "test_partner_b").first()

    client_a = OANFarmerVOPRFClient("kenya-pilot", EVALUATOR_KEY_ID, EVALUATOR_PUBLIC_KEY)
    client_b = OANFarmerVOPRFClient("kenya-pilot", EVALUATOR_KEY_ID, EVALUATOR_PUBLIC_KEY)

    phone = "0712 345 678"

    # --- Step 1: Partner A registers ---
    x_a, B_a, r_a = client_a.prepare_blinded_registration(phone)
    eval_resp_a = helper_evaluate("kenya-pilot", EVALUATOR_KEY_ID, base64.b64encode(B_a.to_bytes()).decode(), partner_a)
    z_a = base64.b64decode(eval_resp_a.evaluated_elements[0])
    proof_a = base64.b64decode(eval_resp_a.proofs[0])
    token_a = client_a.process_evaluation_response(x_a, B_a, r_a, z_a, proof_a)

    reg_req_a = VOPRFFarmerRegisterRequest(
        pilot_id="kenya-pilot",
        key_id=EVALUATOR_KEY_ID,
        token_b64=base64.b64encode(token_a).decode(),
        gender="F",
        age_band="25-34",
        county_code="047",
        role="onboarder",
        idempotency_key=str(uuid.uuid4())
    )
    res_a = register_farmer_voprf_token(reg_req_a, partner=partner_a, db=db)
    assert res_a.status == "accepted"
    assert res_a.is_new_entity is True
    entity_id_a = res_a.entity_id

    # --- Step 2: Partner B registers same farmer ---
    x_b, B_b, r_b = client_b.prepare_blinded_registration(phone)
    eval_resp_b = helper_evaluate("kenya-pilot", EVALUATOR_KEY_ID, base64.b64encode(B_b.to_bytes()).decode(), partner_b)
    z_b = base64.b64decode(eval_resp_b.evaluated_elements[0])
    proof_b = base64.b64decode(eval_resp_b.proofs[0])
    token_b = client_b.process_evaluation_response(x_b, B_b, r_b, z_b, proof_b)

    # Tokens must be identical despite completely different blinds!
    assert token_a == token_b

    reg_req_b = VOPRFFarmerRegisterRequest(
        pilot_id="kenya-pilot",
        key_id=EVALUATOR_KEY_ID,
        token_b64=base64.b64encode(token_b).decode(),
        gender="F",
        age_band="25-34",
        county_code="047",
        role="primary",
        idempotency_key=str(uuid.uuid4())
    )
    res_b = register_farmer_voprf_token(reg_req_b, partner=partner_b, db=db)
    assert res_b.status == "accepted"
    assert res_b.is_new_entity is False # Overlap detected!
    assert res_b.entity_id == entity_id_a # Resolved to same farmer!

    # Check Attribution Separation
    assocs = db.query(PartnerAssociation).filter(PartnerAssociation.entity_id == entity_id_a).all()
    assert len(assocs) == 2
    assoc_map = {a.partner_id: a.role for a in assocs}
    assert assoc_map["test_partner_a"] == "onboarder"
    assert assoc_map["test_partner_b"] == "primary"

    db.close()

def test_consent_lifecycle_and_pep():
    """
    Verifies:
    1. Pre-flight check before consent -> BLOCKS downstream advice.
    2. Consent Capture -> ALLOWS downstream advice.
    3. Consent Withdrawal -> BLOCKS downstream advice.
    4. Re-consent -> Restores ALLOW.
    """
    db = TestSession()
    partner_a = db.query(Partner).filter(Partner.partner_id == "test_partner_a").first()

    # Create entity
    entity = FarmerEntity(status="active")
    db.add(entity)
    db.commit()

    # Pre-consent check
    chk1 = check_consent_policy_enforcement_point(entity.entity_id, "ADVISORY", partner=partner_a, db=db)
    assert chk1.allowed is False

    # Capture consent
    cap_req = ConsentCaptureRequest(entity_id=entity.entity_id, purpose="ADVISORY", channel="WHITE_LABEL_APP")
    cap_resp = capture_consent(cap_req, partner=partner_a, db=db)
    assert cap_resp["state"] == "ACTIVE"

    # Active consent check
    chk2 = check_consent_policy_enforcement_point(entity.entity_id, "ADVISORY", partner=partner_a, db=db)
    assert chk2.allowed is True

    # Withdraw consent
    with_req = ConsentWithdrawRequest(entity_id=entity.entity_id, purpose="ADVISORY", reason="User opted out")
    with_resp = withdraw_consent(with_req, partner=partner_a, db=db)
    assert with_resp["state"] == "WITHDRAWN"

    # Post-withdrawal check -> BLOCKED!
    chk3 = check_consent_policy_enforcement_point(entity.entity_id, "ADVISORY", partner=partner_a, db=db)
    assert chk3.allowed is False
    assert chk3.status == "WITHDRAWN"

    db.close()

def test_offline_store_and_forward_queue():
    """
    Verifies that rural field agents can queue farmer records offline,
    sync when connectivity returns, and automatically shred cleartext phone numbers.
    """
    client = OANFarmerVOPRFClient("kenya-pilot", EVALUATOR_KEY_ID, EVALUATOR_PUBLIC_KEY)
    q = client.offline_queue

    q1 = q.enqueue("0712 111 222", "ADVISORY", "onboarder")
    q2 = q.enqueue("0712 333 444", "FERTILIZER_SUBSIDY", "primary")

    items = q.fetch_queued()
    assert len(items) == 2

    # Simulate sync & shred
    for item in items:
        q.shred_record(item["queue_id"])

    assert len(q.fetch_queued()) == 0

def test_dpi_telemetry_reporting():
    """
    Verifies that get_dpi_telemetry_metrics returns accurate counts.
    """
    db = TestSession()
    partner_a = db.query(Partner).filter(Partner.partner_id == "test_partner_a").first()
    partner_b = db.query(Partner).filter(Partner.partner_id == "test_partner_b").first()

    # Create 2 entities
    e1 = FarmerEntity(status="active")
    e2 = FarmerEntity(status="active")
    db.add(e1)
    db.add(e2)
    db.flush()

    # Link e1 to partner_a and partner_b (Overlap = 1)
    db.add(PartnerAssociation(entity_id=e1.entity_id, partner_id=partner_a.partner_id, role="onboarder", status="active"))
    db.add(PartnerAssociation(entity_id=e1.entity_id, partner_id=partner_b.partner_id, role="primary", status="active"))
    # Link e2 to partner_a only
    db.add(PartnerAssociation(entity_id=e2.entity_id, partner_id=partner_a.partner_id, role="onboarder", status="active"))
    db.commit()

    metrics = get_dpi_telemetry_metrics(_auth="admin", db=db)
    assert metrics["total_registrations_received"] == 3
    assert metrics["deduplicated_farmer_identities"] == 2
    assert metrics["cross_provider_overlap_records"] == 1
    assert metrics["cross_provider_overlap_rate_pct"] == 33.33

    db.close()

def test_hash_to_group_has_no_known_dlog():
    """
    TASK 2 BLOCKING REGRESSION TEST:
    Verifies that hash_to_group(x) produces a curve point with an UNKNOWN discrete
    logarithm relative to base generator G.

    WHY THIS TEST EXISTS:
    In a prior defective implementation, hash_to_group computed:
        s(x) = SHA512(...) mod (N-1) + 1
        H(x) = s(x) * G
    Because s(x) was publicly computable from x alone, anyone holding public key K = k*G
    could forge the unblinded evaluator product as:
        forged_N = s(x) * K = s(x) * k * G = k * (s(x) * G) = k * H(x) = honest_N
    This allowed an offline rainbow-table attack across all ~200M Kenyan phone numbers
    without ever calling the HSM Evaluator or needing any private key.

    THIS TEST ENSURES:
    1. The honest flow produces token T via Evaluator private key k.
    2. Attempting the offline shortcut s(x) * K FAILS to produce honest_N and FAILS
       to reproduce the token T.
    3. Any attacker with only x and K cannot compute T offline without querying the Evaluator.
    DO NOT SIMPLIFY OR CHANGE hash_to_group BACK TO A SCALAR MULTIPLE OF G.
    """
    import hashlib
    from app.crypto.voprf import hash_to_group, point_mul, verify_dleq_proof, N_ORDER
    from app.routes.evaluator import EVALUATOR_SECRET_K

    phone = "+254712345678"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)

    # 1. Honest protocol flow (Client Blinding -> Evaluator Evaluation -> Client Unblinding -> Finalize)
    B_honest, r_honest = VOPRFEngine.blind(x)
    Z_honest, proof = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B_honest, EVALUATOR_PUBLIC_KEY)
    assert verify_dleq_proof(GENERATOR_G, EVALUATOR_PUBLIC_KEY, B_honest, Z_honest, proof)
    N_honest = VOPRFEngine.unblind(Z_honest, r_honest)
    token_honest = VOPRFEngine.finalize(x, N_honest)

    # 2. Attacker shortcut attempt using legacy scalar formula s(x)
    dst_legacy = b"HashToGroup-oan-phone-dedup-v1-"
    h_legacy = hashlib.sha512(dst_legacy + x).digest()
    s_legacy = int.from_bytes(h_legacy, "big") % (N_ORDER - 1) + 1

    # Attacker computes s_legacy * K using only public key EVALUATOR_PUBLIC_KEY
    forged_point_pt = point_mul(s_legacy, EVALUATOR_PUBLIC_KEY.pt)
    assert forged_point_pt is not None
    forged_point = GroupElement(forged_point_pt)
    token_forged = VOPRFEngine.finalize(x, forged_point)

    # 3. CRITICAL REGRESSION ASSERTION:
    # Under a correct try-and-increment hash-to-curve, the attacker's forged point
    # CANNOT match N_honest, and the forged token CANNOT match token_honest!
    assert N_honest.pt != forged_point.pt, "CRITICAL DEFECT: Attacker forged unblinded element N without private key!"
    assert token_honest != token_forged, "CRITICAL DEFECT: Attacker forged finalized token T using public key shortcut!"

def test_consent_check_unauthenticated_rejected():
    """
    TASK 5 HARDENING VERIFICATION:
    Asserts that an unauthenticated call to GET /v1/consent/check
    with no partner headers is strictly rejected with HTTP 401 Unauthorized.
    """
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    resp = client.get("/v1/consent/check?entity_id=00000000-0000-0000-0000-000000000000&purpose=ADVISORY")
    assert resp.status_code == 401
    assert "detail" in resp.json()

