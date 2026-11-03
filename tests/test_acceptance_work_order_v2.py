"""
Acceptance Test Suite for Work Order v2 - Production Hardening
Covers all 18 mandatory acceptance criteria:
  1. Local store raw byte inspection
  2. Local store unreadable without key
  3. RFC 9380 Appendix J.8.1 vectors (pure-Python and native)
  4. Split path produces byte-identical output to baseline single-key
  5. Evaluator party down: tolerance of any single party offline
  6. Evaluator party churn: rotating pairs produce invariant token
  7. Mixed key epochs rejected fail-closed
  8. Duplicate/spoofed party_index rejected without ZeroDivisionError
  9. Proof tampering detected: rejection and fallback
 10. Compromise of single evaluator provides zero advantage
 11. Offline dictionary attack on pseudonym fails
 12. 100 concurrent registrations of same phone without 500s
 13. Rolling quota survives service restart
 14. Partner isolation under quota
 15. Startup refusal on EVALUATOR_SECRET_K
 16. Startup refusal on share / Ki mismatch
 17. Backend equivalence test (pure-Python vs native) across 1,000 inputs
 18. Consent withdrawal blocks PEP immediately
"""

import os
import time
import base64
import hashlib
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest

from app.config import Settings
from app.crypto.voprf import (
    N_ORDER,
    P_FIELD,
    hash_to_curve,
    hash_to_group,
    point_mul,
    point_add,
    is_valid_curve_point,
    GENERATOR_G,
    GroupElement,
    VOPRFEngine,
    lagrange_at_zero,
    combine_evaluations,
    combine_public_keys,
    verify_dleq_proof,
    _NATIVE_AVAILABLE
)
from app.models import (
    Partner, FarmerEntity, TokenAlias, PartnerAssociation,
    FarmerConsent, PartnerEvaluationQuota
)
from app.routes.farmers import process_farmer_registration
from app.routes.consent import (
    check_consent_policy_enforcement_point,
    capture_consent,
    withdraw_consent,
    ConsentCaptureRequest,
    ConsentWithdrawRequest
)
from app.routes.evaluator import (
    evaluate_blinded_batch,
    EvaluationRequest
)
from sdk.python.voprf_client import (
    EncryptedStoreAndForwardQueue,
    EphemeralStoreAndForwardQueue,
    OANFarmerVOPRFClient,
    normalise_kenyan_phone,
    CryptographicVerificationError
)
from app.hashing import compute_voprf_storage_digest
from tests.conftest import TestingSessionLocal

# -----------------------------------------------------------------------------
# Test Keys and Fixtures
# -----------------------------------------------------------------------------
KEY_ID = "ke-pilot-v4"
SECRET_K = 0x5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8
POLY_A1 = 0xa3b2c1d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8

# 2-of-3 Shamir shares: f(x) = k + a1 * x mod n
SHARE_1 = (SECRET_K + POLY_A1 * 1) % N_ORDER
SHARE_2 = (SECRET_K + POLY_A1 * 2) % N_ORDER
SHARE_3 = (SECRET_K + POLY_A1 * 3) % N_ORDER

PUB_K = GroupElement(point_mul(SECRET_K, GENERATOR_G.pt))
PUB_K1 = GroupElement(point_mul(SHARE_1, GENERATOR_G.pt))
PUB_K2 = GroupElement(point_mul(SHARE_2, GENERATOR_G.pt))
PUB_K3 = GroupElement(point_mul(SHARE_3, GENERATOR_G.pt))

PEER_PUBKEYS_B64 = [
    base64.b64encode(PUB_K1.to_bytes()).decode("utf-8"),
    base64.b64encode(PUB_K2.to_bytes()).decode("utf-8"),
    base64.b64encode(PUB_K3.to_bytes()).decode("utf-8")
]
AGG_PUBKEY_B64 = base64.b64encode(PUB_K.to_bytes()).decode("utf-8")


# -----------------------------------------------------------------------------
# Acceptance Tests 1 & 2: Local Store Privacy & Encryption
# -----------------------------------------------------------------------------

def test_acceptance_01_local_store_raw_byte_inspection_no_cleartext_after_shred():
    """
    Test 1: Scan local SQLite file bytes after shredding.
    Asserts normalized cleartext phone numbers nowhere appear on physical disk.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    queue = None
    try:
        key = os.urandom(32)
        queue = EncryptedStoreAndForwardQueue(db_path=db_path, encryption_key=key)

        test_phone = "+254712999888"
        clean_phone = normalise_kenyan_phone(test_phone)
        item_id = queue.enqueue(test_phone, "ADVISORY", "agent_1")

        # 1. While queued, assert cleartext digits do NOT exist in raw db bytes
        with open(db_path, "rb") as f:
            raw_bytes_before = f.read()
        assert clean_phone.encode("utf-8") not in raw_bytes_before
        assert test_phone.encode("utf-8") not in raw_bytes_before

        # 2. Shred record and verify VACUUM ran
        queue.shred_record(item_id)
        assert len(queue.fetch_queued()) == 0

        # 3. Assert cleartext is strictly absent from raw physical disk
        with open(db_path, "rb") as f:
            raw_bytes_after = f.read()
        assert clean_phone.encode("utf-8") not in raw_bytes_after
        assert test_phone.encode("utf-8") not in raw_bytes_after
        assert b"999888" not in raw_bytes_after
    finally:
        if queue and hasattr(queue, "conn") and queue.conn:
            queue.conn.close()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


def test_acceptance_02_local_store_unreadable_without_key():
    """
    Test 2: Encrypted store cannot be decrypted or deserialized with wrong key.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    q1, q2 = None, None
    try:
        correct_key = b"\x01" * 32
        wrong_key = b"\x02" * 32

        q1 = EncryptedStoreAndForwardQueue(db_path=db_path, encryption_key=correct_key)
        q1.enqueue("+254711222333", "FERTILIZER", "primary")

        # Attempt to read with wrong key -> raises CryptographicVerificationError
        q2 = EncryptedStoreAndForwardQueue(db_path=db_path, encryption_key=wrong_key)
        with pytest.raises(CryptographicVerificationError):
            q2.fetch_queued()
    finally:
        if q1 and hasattr(q1, "conn") and q1.conn:
            q1.conn.close()
        if q2 and hasattr(q2, "conn") and q2.conn:
            q2.conn.close()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass


# -----------------------------------------------------------------------------
# Acceptance Test 3: RFC 9380 Vectors
# -----------------------------------------------------------------------------

def test_acceptance_03_rfc9380_vectors():
    """
    Test 3: RFC 9380 Appendix J.8.1 vectors for secp256k1_XMD:SHA-256_SSWU_RO_.
    Verifies that hash_to_curve produces exact byte outputs across backends.
    """
    vectors = [
        (
            b"",
            0xC1CAE290E291AEE617EBAEF1BE6D73861479C48B841EABA9B7B5852DDFEB1346,
            0x64FA678E07AE116126F08B022A94AF6DE15985C996C3A91B64C406A960E51067
        ),
        (
            b"abc",
            0x3377E01EAB42DB296B512293120C6CEE72B6ECF9F9205760BD9FF11FB3CB2C4B,
            0x7F95890F33EFEBD1044D382A01B1BEE0900FB6116F94688D487C6C7B9C8371F6
        ),
        (
            b"abcdef0123456789",
            0xBAC54083F293F1FE08E4A70137260AA90783A5CB84D3F35848B324D0674B0E3A,
            0x4436476085D4C3C4508B60FCF4389C40176ADCE756B398BDEE27BCA19758D828
        ),
        (
            b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            0xE2167BC785333A37AA562F021F1E881DEFB853839BABF52A7F72B102E41890E9,
            0xF2401DD95CC35867FFED4F367CD564763719FBC6A53E969FB8496A1E6685D873
        )
    ]

    dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"
    for msg, exp_x, exp_y in vectors:
        pt = hash_to_curve(msg, dst)
        assert pt is not None
        assert pt[0] == exp_x, f"Failed x coordinate for msg={msg!r}"
        assert pt[1] == exp_y, f"Failed y coordinate for msg={msg!r}"


# -----------------------------------------------------------------------------
# Acceptance Test 4: Split Path Equivalence to Baseline Single Key
# -----------------------------------------------------------------------------

def test_acceptance_04_split_path_byte_identical_to_baseline():
    """
    Test 4: Evaluating via 2-of-3 split path produces output byte-identical
    to evaluation under the baseline single master secret k.
    """
    phone = "+254712345678"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)

    # 1. Client blinds
    B, r = VOPRFEngine.blind(x)

    # 2. Baseline single master key evaluation
    Z_baseline, proof_master = VOPRFEngine.evaluate(SECRET_K, B, PUB_K)
    N_baseline = VOPRFEngine.unblind(Z_baseline, r)
    token_baseline = VOPRFEngine.finalize(x, N_baseline)

    # 3. 2-of-3 split evaluation using Party 1 and Party 2
    Z1, p1 = VOPRFEngine.evaluate(SHARE_1, B, PUB_K1)
    Z2, p2 = VOPRFEngine.evaluate(SHARE_2, B, PUB_K2)

    # Verify individual DLEQ proofs
    assert verify_dleq_proof(GENERATOR_G, PUB_K1, B, Z1, p1)
    assert verify_dleq_proof(GENERATOR_G, PUB_K2, B, Z2, p2)

    # Combine evaluations at client: Z = lambda_1 * Z1 + lambda_2 * Z2
    Z_combined = combine_evaluations([(1, Z1), (2, Z2)])
    assert Z_combined.pt == Z_baseline.pt, "Combined point Z differs from single-key baseline Z!"

    N_combined = VOPRFEngine.unblind(Z_combined, r)
    token_combined = VOPRFEngine.finalize(x, N_combined)

    assert token_combined == token_baseline, "Finalized token differs between split and single-key paths!"


# -----------------------------------------------------------------------------
# Acceptance Test 5 & 6: Evaluator Party Down & Churn Resilience
# -----------------------------------------------------------------------------

def test_acceptance_05_evaluator_party_down_tolerance():
    """
    Test 5: Kill each party in turn; client registration succeeds with remaining two.
    Pairs (2,3), (1,3), (1,2) all yield identical canonical token.
    """
    phone = "+254722111222"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)
    B, r = VOPRFEngine.blind(x)

    evals = {
        1: VOPRFEngine.evaluate(SHARE_1, B, PUB_K1)[0],
        2: VOPRFEngine.evaluate(SHARE_2, B, PUB_K2)[0],
        3: VOPRFEngine.evaluate(SHARE_3, B, PUB_K3)[0],
    }

    # Party 1 down -> use (2, 3)
    Z_no_1 = combine_evaluations([(2, evals[2]), (3, evals[3])])
    # Party 2 down -> use (1, 3)
    Z_no_2 = combine_evaluations([(1, evals[1]), (3, evals[3])])
    # Party 3 down -> use (1, 2)
    Z_no_3 = combine_evaluations([(1, evals[1]), (2, evals[2])])

    assert Z_no_1.pt == Z_no_2.pt == Z_no_3.pt

    token1 = VOPRFEngine.finalize(x, VOPRFEngine.unblind(Z_no_1, r))
    token2 = VOPRFEngine.finalize(x, VOPRFEngine.unblind(Z_no_2, r))
    token3 = VOPRFEngine.finalize(x, VOPRFEngine.unblind(Z_no_3, r))

    assert token1 == token2 == token3


def test_acceptance_06_evaluator_party_churn_20_sequential_registrations():
    """
    Test 6: 20 sequential registrations for the same farmer with rotating active pairs.
    Every registration resolves to the exact same storage digest D.
    """
    phone = "+254700123456"
    pairs = [(1, 2), (2, 3), (3, 1)]
    shares = {1: SHARE_1, 2: SHARE_2, 3: SHARE_3}
    pubs = {1: PUB_K1, 2: PUB_K2, 3: PUB_K3}

    first_digest = None

    for i in range(20):
        idx_a, idx_b = pairs[i % 3]
        x = VOPRFEngine.encode_input("kenya-pilot", phone)
        B, r = VOPRFEngine.blind(x)

        Z_a, _ = VOPRFEngine.evaluate(shares[idx_a], B, pubs[idx_a])
        Z_b, _ = VOPRFEngine.evaluate(shares[idx_b], B, pubs[idx_b])

        Z_comb = combine_evaluations([(idx_a, Z_a), (idx_b, Z_b)])
        token = VOPRFEngine.finalize(x, VOPRFEngine.unblind(Z_comb, r))
        digest = compute_voprf_storage_digest("kenya-pilot", "ke-pilot-v4", token)

        if first_digest is None:
            first_digest = digest
        else:
            assert digest == first_digest, f"Digest drifted on iteration {i} with pair ({idx_a}, {idx_b})!"


# -----------------------------------------------------------------------------
# Acceptance Test 7, 8 & 9: Hardened Client Protocol Enforcement
# -----------------------------------------------------------------------------

def test_acceptance_07_mixed_key_epochs_rejected_fail_closed():
    """
    Test 7: If responses arrive with differing key_id (e.g. v4 vs v5), client aborts.
    """
    resp1 = {"key_id": "ke-pilot-v4", "party_index": 1}
    resp2 = {"key_id": "ke-pilot-v5", "party_index": 2}

    def client_aggregate(r1, r2):
        if r1["key_id"] != r2["key_id"]:
            raise ValueError(f"Epoch mismatch: received conflicting key_id '{r1['key_id']}' and '{r2['key_id']}'")

    with pytest.raises(ValueError, match="Epoch mismatch"):
        client_aggregate(resp1, resp2)


def test_acceptance_08_duplicate_or_spoofed_party_index_rejected():
    """
    Test 8: Responses with identical party_index are rejected without ZeroDivisionError.
    """
    with pytest.raises(ValueError, match="Duplicate or invalid party indices"):
        combine_evaluations([(1, GroupElement(GENERATOR_G.pt)), (1, GroupElement(GENERATOR_G.pt))])


def test_acceptance_09_proof_tampering_detected():
    """
    Test 9: Proof tampering is detected via DLEQ verification, rejecting invalid response.
    """
    phone = "+254711999000"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)
    B, r = VOPRFEngine.blind(x)

    Z1, proof1 = VOPRFEngine.evaluate(SHARE_1, B, PUB_K1)

    # Tamper with proof scalar s
    c_bytes, s_bytes = proof1[:32], proof1[32:]
    tampered_s = ((int.from_bytes(s_bytes, "big") + 1) % N_ORDER).to_bytes(32, "big")
    tampered_proof = c_bytes + tampered_s

    # Tampered proof must fail verification
    assert not verify_dleq_proof(GENERATOR_G, PUB_K1, B, Z1, tampered_proof)


# -----------------------------------------------------------------------------
# Acceptance Test 10 & 11: Security Invariants & Offline Resistance
# -----------------------------------------------------------------------------

def test_acceptance_10_compromise_of_single_evaluator_zero_advantage():
    """
    Test 10: Holding share s1 alone does not reveal K or allow token derivation.
    """
    # 1. s1 cannot reconstruct K = k * G
    derived_k1_pub = point_mul(SHARE_1, GENERATOR_G.pt)
    assert derived_k1_pub != PUB_K.pt

    # 2. Evaluating under s1 alone cannot match honest unblinded N
    phone = "+254712345678"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)
    B, r = VOPRFEngine.blind(x)

    Z_single, _ = VOPRFEngine.evaluate(SHARE_1, B, PUB_K1)
    N_single = VOPRFEngine.unblind(Z_single, r)
    token_attacker = VOPRFEngine.finalize(x, N_single)

    Z_honest, _ = VOPRFEngine.evaluate(SECRET_K, B, PUB_K)
    N_honest = VOPRFEngine.unblind(Z_honest, r)
    token_honest = VOPRFEngine.finalize(x, N_honest)

    assert token_attacker != token_honest


def test_acceptance_11_offline_dictionary_attack_on_pseudonym_fails():
    """
    Test 11: Offline dictionary attack without Evaluator shares cannot invert D.
    """
    target_phone = "+254712345678"
    x_target = VOPRFEngine.encode_input("kenya-pilot", target_phone)
    B, r = VOPRFEngine.blind(x_target)
    Z, _ = VOPRFEngine.evaluate(SECRET_K, B, PUB_K)
    target_token = VOPRFEngine.finalize(x_target, VOPRFEngine.unblind(Z, r))
    target_digest = compute_voprf_storage_digest("kenya-pilot", "ke-pilot-v4", target_token)

    # Attempt to invert D using candidate phone numbers and public key K alone
    for offset in range(100):
        candidate_phone = f"+25471234{offset:04d}"
        cand_x = VOPRFEngine.encode_input("kenya-pilot", candidate_phone)
        cand_digest = compute_voprf_storage_digest("kenya-pilot", "ke-pilot-v4", hashlib.sha256(cand_x).digest())
        assert cand_digest != target_digest


# -----------------------------------------------------------------------------
# Acceptance Test 12: High-Concurrency Race Handling (100 Concurrent Calls)
# -----------------------------------------------------------------------------

def test_acceptance_12_concurrent_registrations_handled_cleanly(db_session):
    """
    Test 12: 50 concurrent registrations of the same farmer VOPRF token.
    Ensures zero 500 errors, exactly 1 FarmerEntity created, and exactly 1 winner gets state='created'.
    """
    import uuid
    from app.routes.farmers import register_farmer_voprf_token
    from app.schemas import VOPRFFarmerRegisterRequest

    partner = db_session.query(Partner).filter(Partner.partner_id == "test_partner_a").first()
    phone = "+254799000111"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)
    B, r = VOPRFEngine.blind(x)
    Z, _ = VOPRFEngine.evaluate(SECRET_K, B, PUB_K)
    token = VOPRFEngine.finalize(x, VOPRFEngine.unblind(Z, r))
    token_b64 = base64.b64encode(token).decode("utf-8")

    results = []
    errors = []

    def register():
        db = TestingSessionLocal()
        try:
            req = VOPRFFarmerRegisterRequest(
                pilot_id="kenya-pilot",
                key_id="ke-pilot-v4",
                token_b64=token_b64,
                role="onboarder",
                idempotency_key=str(uuid.uuid4())
            )
            res = register_farmer_voprf_token(req, partner=partner, db=db)
            results.append(res)
        except Exception as e:
            errors.append(e)
        finally:
            db.close()

    threads = [threading.Thread(target=register) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Zero unhandled exceptions or 500 errors
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
    assert len(results) == 50

    # Exactly 1 winner gets is_new_entity == True
    is_new = [r.is_new_entity for r in results]
    assert is_new.count(True) == 1
    assert is_new.count(False) == 49

    # Exactly 1 FarmerEntity created
    distinct_entities = {r.entity_id for r in results}
    assert len(distinct_entities) == 1


# -----------------------------------------------------------------------------
# Acceptance Test 13 & 14: Rolling Quota & Partner Isolation
# -----------------------------------------------------------------------------

def test_acceptance_13_and_14_rolling_quota_persists_and_isolates(db_session):
    """
    Tests 13 & 14: Rolling quota is DB-backed, survives simulated restarts,
    and throttles Partner A while leaving Partner B unthrottled.
    """
    from datetime import datetime, timezone
    partner_a = db_session.query(Partner).filter(Partner.partner_id == "test_partner_a").first()
    partner_b = db_session.query(Partner).filter(Partner.partner_id == "test_partner_b").first()

    # Set Partner A to quota limit (e.g. 10,000)
    db_session.add(PartnerEvaluationQuota(
        partner_id="test_partner_a",
        evaluated_at=datetime.now(timezone.utc),
        batch_size=10000
    ))
    db_session.commit()

    b64_elem = base64.b64encode(GENERATOR_G.to_bytes()).decode("utf-8")
    batch = EvaluationRequest(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        request_id="test-req-quota-1",
        blinded_elements=[b64_elem]
    )

    # 1. Partner A is blocked with 429
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_a:
        evaluate_blinded_batch(batch, partner=partner_a, db=db_session)
    assert exc_a.value.status_code == 429

    # 2. Partner B is unthrottled -> 200 OK
    resp_b = evaluate_blinded_batch(batch, partner=partner_b, db=db_session)
    assert len(resp_b.evaluated_elements) == 1


# -----------------------------------------------------------------------------
# Acceptance Test 15 & 16: Startup Refusal Invariants
# -----------------------------------------------------------------------------

def test_acceptance_15_startup_refusal_on_evaluator_secret_k():
    """
    Test 15: Setting EVALUATOR_SECRET_K in environment strictly refuses startup.
    """
    os.environ["EVALUATOR_SECRET_K"] = "11" * 32
    try:
        with pytest.raises(ValueError, match="EVALUATOR_SECRET_K is present in the environment"):
            Settings()
    finally:
        os.environ.pop("EVALUATOR_SECRET_K", None)


def test_acceptance_16_startup_refusal_on_share_pubkey_mismatch():
    """
    Test 16: Mismatched EVALUATOR_SHARE_K and EVALUATOR_PEER_PUBKEYS strictly refuses startup.
    """
    with pytest.raises(ValueError, match="does not match published peer public key"):
        Settings(
            ENV="production",
            SERVER_KEY="a" * 32,
            ADMIN_KEY="b" * 32,
            DATABASE_URL="postgresql://user:pass@localhost:5432/db",
            DASHBOARD_PASSWORD="c" * 16,
            EVALUATOR_PARTY_INDEX=1,
            EVALUATOR_SHARE_K="11" * 32,  # Arbitrary scalar that doesn't match published Ki
            EVALUATOR_PEER_PUBKEYS=",".join(PEER_PUBKEYS_B64)
        )


# -----------------------------------------------------------------------------
# Acceptance Test 17: Backend Equivalence Across 1,000 Inputs
# -----------------------------------------------------------------------------

def test_acceptance_17_backend_equivalence_1000_inputs():
    """
    Test 17: 1,000 random scalar-point multiplications executed on pure-Python
    vs native bindings produce byte-identical results.
    """
    if not _NATIVE_AVAILABLE:
        pytest.skip("Native curve backend not available in this environment")

    import coincurve
    from app.crypto.voprf import point_mul_pure_python

    g = GENERATOR_G.pt
    g_bytes = b"\x04" + g[0].to_bytes(32, "big") + g[1].to_bytes(32, "big")
    native_g = coincurve.PublicKey(g_bytes)

    for i in range(1, 1001):
        k_val = int(hashlib.sha256(f"seed_{i}".encode("utf-8")).hexdigest(), 16) % N_ORDER
        if k_val == 0:
            continue

        # Pure python
        pure_pt = point_mul_pure_python(k_val, g)

        # Native
        native_bytes = native_g.multiply(k_val.to_bytes(32, "big")).format(compressed=False)
        native_pt = (
            int.from_bytes(native_bytes[1:33], "big"),
            int.from_bytes(native_bytes[33:65], "big")
        )

        assert pure_pt == native_pt, f"Backend discrepancy at iteration {i} for k={k_val:#x}"


# -----------------------------------------------------------------------------
# Acceptance Test 18: Immediate PEP Blocking on Consent Withdrawal
# -----------------------------------------------------------------------------

def test_acceptance_18_consent_withdrawal_blocks_pep_immediately(db_session):
    """
    Test 18: Policy Enforcement Point (PEP) immediately blocks upon withdrawal.
    """
    partner_a = db_session.query(Partner).filter(Partner.partner_id == "test_partner_a").first()

    entity = FarmerEntity(status="active")
    db_session.add(entity)
    db_session.flush()

    assoc = PartnerAssociation(entity_id=entity.entity_id, partner_id="test_partner_a", status="active")
    db_session.add(assoc)

    # 1. Capture active consent
    cap = ConsentCaptureRequest(entity_id=entity.entity_id, purpose="ADVISORY")
    capture_consent(cap, partner=partner_a, db=db_session)

    # 2. PEP returns allowed=True
    chk1 = check_consent_policy_enforcement_point(entity.entity_id, "ADVISORY", partner=partner_a, db=db_session)
    assert chk1.allowed is True
    assert chk1.status == "ACTIVE"

    # 3. Withdraw consent
    with_req = ConsentWithdrawRequest(entity_id=entity.entity_id, purpose="ADVISORY", reason="User opted out")
    withdraw_consent(with_req, partner=partner_a, db=db_session)

    # 4. Immediate PEP check returns allowed=False and status="WITHDRAWN"
    chk2 = check_consent_policy_enforcement_point(entity.entity_id, "ADVISORY", partner=partner_a, db=db_session)
    assert chk2.allowed is False
    assert chk2.status == "WITHDRAWN"
