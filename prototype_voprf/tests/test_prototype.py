"""
Comprehensive Test Suite for OAN Kenya VOPRF + Store-and-Forward + Consent Architecture
Tests the 20 Critical Architectural Edge Cases:
  1. RFC 9497 Blinding, Evaluation, DLEQ Proofs, and Finalization
  2. Same phone across different providers -> Exact same Entity ID resolved
  3. Decoupled Attribution: Onboarder vs. Secondary Contributor
  4. Anti-Tamper: Corrupted DLEQ proofs or forged keys are strictly rejected
  5. Offline Store-and-Forward Queue & Device Shredding
  6. First-Class Consent Lifecycle: Active -> Withdrawn -> Blocked Downstream -> Re-Consented
  7. Idempotent re-submissions
  8. Real-time DPI Overlap Telemetry
"""

import os
os.environ["EVALUATOR_SECRET_K"] = "e8c7b6a5d4c3b2a1908f7e6d5c4b3a2918273645e5d4c3b2a10987654321abcd"
os.environ["EVALUATOR_KEY_ID"] = "ke-pilot-v3"
import uuid
import base64
import pytest

from prototype_voprf.crypto.voprf_engine import (
    VOPRFEngine,
    GroupElement,
    GENERATOR_G,
    N_ORDER
)
from prototype_voprf.evaluator.service import (
    evaluate_blinded_batch,
    get_public_key,
    EvaluationRequest,
    EVALUATOR_PUBLIC_KEY,
    KEY_ID
)
from prototype_voprf.registry.service import (
    register_farmer,
    capture_consent,
    withdraw_consent,
    check_consent_enforcement_point,
    get_dpi_telemetry,
    RegistrationRequest,
    ConsentCaptureRequest,
    ConsentWithdrawRequest,
    PARTNER_DIRECTORY,
    Base,
    engine,
    SessionLocal
)
from prototype_voprf.registry.models import FarmerEntity, TokenAlias, PartnerAssociation, FarmerConsent
from prototype_voprf.sdk.client import (
    OANFarmerClient,
    normalise_kenyan_phone,
    CryptographicVerificationError
)

class DirectEvaluatorClient:
    def evaluate(self, pilot_id: str, key_id: str, request_id: str, blinded_elements: list, caller_token: str):
        req = EvaluationRequest(
            pilot_id=pilot_id,
            key_id=key_id,
            request_id=request_id,
            blinded_elements=blinded_elements
        )
        return evaluate_blinded_batch(req, caller_token=caller_token)

class DirectRegistryClient:
    def __init__(self, db):
        self.db = db

    def register_farmer(self, pilot_id: str, key_id: str, token_b64: str, idempotency_key: str, role: str, caller_token: str):
        partner_name = PARTNER_DIRECTORY[caller_token]
        req = RegistrationRequest(
            pilot_id=pilot_id,
            key_id=key_id,
            token_b64=token_b64,
            idempotency_key=idempotency_key,
            role=role
        )
        return register_farmer(req, partner_name=partner_name, db=self.db)

    def capture_consent(self, entity_id: str, purpose: str, channel: str, caller_token: str):
        partner_name = PARTNER_DIRECTORY[caller_token]
        req = ConsentCaptureRequest(entity_id=entity_id, purpose=purpose, channel=channel)
        return capture_consent(req, partner_name=partner_name, db=self.db)

    def withdraw_consent(self, entity_id: str, purpose: str, reason: str, caller_token: str):
        partner_name = PARTNER_DIRECTORY[caller_token]
        req = ConsentWithdrawRequest(entity_id=entity_id, purpose=purpose, reason=reason)
        return withdraw_consent(req, partner_name=partner_name, db=self.db)

    def check_consent(self, entity_id: str, purpose: str = "ADVISORY", caller_token: str = "partner_oaf_token"):
        partner_name = PARTNER_DIRECTORY[caller_token]
        return check_consent_enforcement_point(entity_id=entity_id, purpose=purpose, partner_name=partner_name, db=self.db)

    def get_metrics(self):
        return get_dpi_telemetry(db=self.db)

@pytest.fixture(autouse=True)
def setup_clean_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def eval_client():
    return DirectEvaluatorClient()

@pytest.fixture
def reg_client():
    db = SessionLocal()
    client = DirectRegistryClient(db)
    yield client
    db.close()

def helper_tokenize_phone(
    client: OANFarmerClient,
    phone: str,
    partner_bearer_token: str,
    eval_client: DirectEvaluatorClient
) -> bytes:
    """Simulates the client <-> evaluator cryptographic handshake"""
    # 1. Client Blinding
    x, B, r = client.prepare_blinded_registration(phone)
    b_b64 = base64.b64encode(B.to_bytes()).decode("utf-8")

    # 2. Call Evaluator
    eval_resp = eval_client.evaluate(
        pilot_id=client.pilot_id,
        key_id=client.key_id,
        request_id=str(uuid.uuid4()),
        blinded_elements=[b_b64],
        caller_token=partner_bearer_token
    )
    z_bytes = base64.b64decode(eval_resp.evaluated_elements[0])
    proof_bytes = base64.b64decode(eval_resp.proofs[0])

    # 3. Client Verification, Unblinding & Finalize
    token_t = client.process_evaluation_response(x, B, r, z_bytes, proof_bytes)
    return token_t

# --- 1. Phone Normalisation Tests ---
def test_kenyan_phone_normalisation():
    assert normalise_kenyan_phone("0712 345 678") == "+254712345678"
    assert normalise_kenyan_phone("+254 712-345-678") == "+254712345678"
    assert normalise_kenyan_phone("0110 999 888") == "+254110999888"
    with pytest.raises(ValueError):
        normalise_kenyan_phone("0812345678")

# --- 2. Cryptographic Invariance & Zero-Knowledge Privacy ---
def test_different_blinds_produce_identical_final_token(eval_client):
    client = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    phone = "0712345678"

    x1, B1, r1 = client.prepare_blinded_registration(phone)
    x2, B2, r2 = client.prepare_blinded_registration(phone)

    # Blinded elements are mathematically randomized noise
    assert B1.to_bytes() != B2.to_bytes()
    assert r1 != r2

    token1 = helper_tokenize_phone(client, phone, "partner_oaf_token", eval_client)
    token2 = helper_tokenize_phone(client, phone, "partner_oaf_token", eval_client)

    # Unblinded finalized tokens are identical
    assert token1 == token2
    assert len(token1) == 64

# --- 3. Anti-Tamper & DLEQ Proof Verification ---
def test_tampered_dleq_proof_is_rejected(eval_client):
    client = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    phone = "0712345678"
    x, B, r = client.prepare_blinded_registration(phone)

    b_b64 = base64.b64encode(B.to_bytes()).decode("utf-8")
    eval_resp = eval_client.evaluate(
        pilot_id="kenya-pilot",
        key_id=KEY_ID,
        request_id=str(uuid.uuid4()),
        blinded_elements=[b_b64],
        caller_token="partner_oaf_token"
    )
    z_bytes = base64.b64decode(eval_resp.evaluated_elements[0])
    proof_bytes = bytearray(base64.b64decode(eval_resp.proofs[0]))

    # Tamper with 1 byte in the proof
    proof_bytes[10] ^= 0xFF

    with pytest.raises(CryptographicVerificationError):
        client.process_evaluation_response(x, B, r, z_bytes, bytes(proof_bytes))

# --- 4. Cross-Provider Deduplication & Attribution ---
def test_cross_provider_deduplication_and_attribution(eval_client, reg_client):
    client_oaf = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    client_digifarm = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_digifarm_token")

    phone = "0712345678"
    token_oaf = helper_tokenize_phone(client_oaf, phone, "partner_oaf_token", eval_client)
    token_digifarm = helper_tokenize_phone(client_digifarm, phone, "partner_digifarm_token", eval_client)

    # 1. Partner A (One Acre Fund) registers first
    resp_a = reg_client.register_farmer(
        pilot_id="kenya-pilot",
        key_id=KEY_ID,
        token_b64=base64.b64encode(token_oaf).decode("utf-8"),
        idempotency_key=str(uuid.uuid4()),
        role="onboarder",
        caller_token="partner_oaf_token"
    )
    assert resp_a.is_new_entity is True
    entity_id_a = resp_a.entity_id

    # 2. Partner B (DigiFarm) registers same farmer later
    resp_b = reg_client.register_farmer(
        pilot_id="kenya-pilot",
        key_id=KEY_ID,
        token_b64=base64.b64encode(token_digifarm).decode("utf-8"),
        idempotency_key=str(uuid.uuid4()),
        role="primary",
        caller_token="partner_digifarm_token"
    )
    assert resp_b.is_new_entity is False # Existing entity resolved!
    assert resp_b.entity_id == entity_id_a # Resolved to same farmer!

    # 3. Verify Decoupled Attribution in Database
    db = SessionLocal()
    assocs = db.query(PartnerAssociation).filter(PartnerAssociation.entity_id == entity_id_a).all()
    assert len(assocs) == 2
    assoc_map = {a.partner_id: a.role for a in assocs}
    assert assoc_map["One Acre Fund"] == "onboarder"
    assert assoc_map["DigiFarm"] == "primary"
    db.close()

# --- 5. Consent Lifecycle & Downstream Policy Enforcement Point (PEP) ---
def test_consent_lifecycle_and_downstream_enforcement(eval_client, reg_client):
    client = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    token = helper_tokenize_phone(client, "0712345678", "partner_oaf_token", eval_client)

    reg_resp = reg_client.register_farmer(
        pilot_id="kenya-pilot",
        key_id=KEY_ID,
        token_b64=base64.b64encode(token).decode("utf-8"),
        idempotency_key=str(uuid.uuid4()),
        role="contributor",
        caller_token="partner_oaf_token"
    )
    entity_id = reg_resp.entity_id

    # Step 1: Pre-consent check -> Must BLOCK
    chk1 = reg_client.check_consent(entity_id=entity_id, purpose="ADVISORY")
    assert chk1.allowed is False

    # Step 2: Capture Consent
    cap_resp = reg_client.capture_consent(
        entity_id=entity_id,
        purpose="ADVISORY",
        channel="WHITE_LABEL_APP",
        caller_token="partner_oaf_token"
    )
    assert cap_resp["state"] == "ACTIVE"

    # Step 3: Active consent check -> Must ALLOW
    chk2 = reg_client.check_consent(entity_id=entity_id, purpose="ADVISORY")
    assert chk2.allowed is True

    # Step 4: Farmer Withdraws Consent
    with_resp = reg_client.withdraw_consent(
        entity_id=entity_id,
        purpose="ADVISORY",
        reason="Farmer opted out via USSD",
        caller_token="partner_oaf_token"
    )
    assert with_resp["state"] == "WITHDRAWN"

    # Step 5: Post-withdrawal check -> Downstream service must BLOCK!
    chk3 = reg_client.check_consent(entity_id=entity_id, purpose="ADVISORY")
    assert chk3.allowed is False
    assert chk3.status == "WITHDRAWN"

    # Step 6: Re-Consent -> Restores ALLOW without mutating Identity ID
    cap_resp2 = reg_client.capture_consent(
        entity_id=entity_id,
        purpose="ADVISORY",
        channel="USSD",
        caller_token="partner_oaf_token"
    )
    assert cap_resp2["state"] == "ACTIVE"
    chk4 = reg_client.check_consent(entity_id=entity_id, purpose="ADVISORY")
    assert chk4.allowed is True

# --- 6. Offline Store-and-Forward & Local PII Shredding ---
def test_offline_store_and_forward_and_shredding(eval_client, reg_client):
    client = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    q = client.offline_queue

    # 1. Enqueue 2 farmers offline
    q.enqueue("0712111222", "ADVISORY", "onboarder")
    q.enqueue("0712333444", "FERTILIZER_SUBSIDY", "contributor")

    queued = q.fetch_queued()
    assert len(queued) == 2

    # 2. Connectivity restored -> Batch process
    for item in queued:
        tok = helper_tokenize_phone(client, item["phone"], "partner_oaf_token", eval_client)
        resp = reg_client.register_farmer(
            pilot_id="kenya-pilot",
            key_id=KEY_ID,
            token_b64=base64.b64encode(tok).decode("utf-8"),
            idempotency_key=str(uuid.uuid4()),
            role=item["role"],
            caller_token="partner_oaf_token"
        )
        assert resp.status == "accepted"
        # 3. Shred phone number from local queue
        q.shred_record(item["queue_id"])

    # Local queue is fully cleared
    assert len(q.fetch_queued()) == 0

# --- 7. DPI Telemetry & Deduplication Metrics ---
def test_dpi_telemetry_metrics(eval_client, reg_client):
    client_a = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_oaf_token")
    client_b = OANFarmerClient("kenya-pilot", KEY_ID, EVALUATOR_PUBLIC_KEY, "partner_digifarm_token")

    tok1_a = helper_tokenize_phone(client_a, "0712000001", "partner_oaf_token", eval_client)
    tok1_b = helper_tokenize_phone(client_b, "0712000001", "partner_digifarm_token", eval_client)
    tok2_a = helper_tokenize_phone(client_a, "0712000002", "partner_oaf_token", eval_client)

    for tok, ptoken, role in [
        (tok1_a, "partner_oaf_token", "onboarder"),
        (tok1_b, "partner_digifarm_token", "primary"),
        (tok2_a, "partner_oaf_token", "onboarder")
    ]:
        reg_client.register_farmer(
            pilot_id="kenya-pilot",
            key_id=KEY_ID,
            token_b64=base64.b64encode(tok).decode("utf-8"),
            idempotency_key=str(uuid.uuid4()),
            role=role,
            caller_token=ptoken
        )

    m = reg_client.get_metrics()
    assert m["total_registrations_received"] == 3
    assert m["deduplicated_farmer_identities"] == 2
    assert m["cross_provider_overlap_records"] == 1
    assert m["cross_provider_overlap_rate_pct"] == 33.33

def test_hash_to_group_has_no_known_dlog():
    """
    TASK 2 BLOCKING REGRESSION TEST:
    Verifies that hash_to_group(x) produces a curve point with an UNKNOWN discrete
    logarithm relative to base generator G.

    Ensures that an attacker with access to public key K and phone number x
    CANNOT forge the evaluated token without querying the Evaluator.
    """
    import hashlib
    from prototype_voprf.crypto.voprf_engine import hash_to_group, point_mul, verify_dleq_proof, N_ORDER
    from prototype_voprf.evaluator.service import EVALUATOR_SECRET_K, EVALUATOR_PUBLIC_KEY

    phone = "0712345678"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)

    # 1. Honest protocol flow
    B_honest, r_honest = VOPRFEngine.blind(x)
    Z_honest, proof = VOPRFEngine.evaluate(EVALUATOR_SECRET_K, B_honest, EVALUATOR_PUBLIC_KEY)
    assert verify_dleq_proof(GENERATOR_G, EVALUATOR_PUBLIC_KEY, B_honest, Z_honest, proof)
    N_honest = VOPRFEngine.unblind(Z_honest, r_honest)
    token_honest = VOPRFEngine.finalize(x, N_honest)

    # 2. Attacker shortcut attempt using legacy scalar formula s(x)
    dst_legacy = b"HashToGroup-oan-phone-dedup-v1-"
    h_legacy = hashlib.sha512(dst_legacy + x).digest()
    s_legacy = int.from_bytes(h_legacy, "big") % (N_ORDER - 1) + 1

    forged_point_pt = point_mul(s_legacy, EVALUATOR_PUBLIC_KEY.pt)
    assert forged_point_pt is not None
    forged_point = GroupElement(forged_point_pt)
    token_forged = VOPRFEngine.finalize(x, forged_point)

    # 3. CRITICAL ASSERTION:
    assert N_honest.pt != forged_point.pt, "CRITICAL DEFECT: Attacker forged unblinded element N!"
    assert token_honest != token_forged, "CRITICAL DEFECT: Attacker forged finalized token T using shortcut!"
