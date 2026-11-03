import pytest
import secrets
from app.crypto.voprf import (
    N_ORDER,
    GENERATOR_G,
    point_mul,
    GroupElement,
    VOPRFEngine
)
from sdk.python.voprf_client import (
    OANFarmerVOPRFClient,
    CryptographicVerificationError,
    ThresholdEvaluationResult
)

@pytest.fixture
def threshold_keys():
    """Generates a fresh 2-of-3 Shamir secret sharing polynomial and public keys."""
    k = secrets.randbelow(N_ORDER - 1) + 1
    a = secrets.randbelow(N_ORDER - 1) + 1

    s1 = (k + a * 1) % N_ORDER
    s2 = (k + a * 2) % N_ORDER
    s3 = (k + a * 3) % N_ORDER

    K = GroupElement(point_mul(k, GENERATOR_G.pt))
    K1 = GroupElement(point_mul(s1, GENERATOR_G.pt))
    K2 = GroupElement(point_mul(s2, GENERATOR_G.pt))
    K3 = GroupElement(point_mul(s3, GENERATOR_G.pt))

    return {
        "k": k,
        "shares": {1: s1, 2: s2, 3: s3},
        "aggregate_K": K,
        "peer_keys": {1: K1, 2: K2, 3: K3}
    }

def test_threshold_evaluation_all_pairs_match_master(threshold_keys):
    """
    Acceptance Test P0-2:
    Drives OANFarmerVOPRFClient through a 2-of-3 evaluation flow using pairs
    {1, 2}, {1, 3}, and {2, 3}, asserting that derived token_bytes matches across
    all three pairs and matches the evaluation under aggregate K.
    """
    client = OANFarmerVOPRFClient(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        evaluator_public_key=threshold_keys["aggregate_K"],
        peer_public_keys=threshold_keys["peer_keys"]
    )

    phone = "+254712345678"
    x, B, r = client.prepare_blinded_registration(phone)

    # 1. Baseline evaluation under master aggregate key K
    Z_master, proof_master = VOPRFEngine.evaluate(
        threshold_keys["k"],
        B,
        threshold_keys["aggregate_K"]
    )
    baseline_token = client.process_evaluation_response(x, B, r, Z_master.to_bytes(), proof_master)

    # 2. Evaluations by all 3 parties
    evals = {}
    for party_idx in (1, 2, 3):
        share_i = threshold_keys["shares"][party_idx]
        K_i = threshold_keys["peer_keys"][party_idx]
        Z_i, proof_i = VOPRFEngine.evaluate(share_i, B, K_i)
        evals[party_idx] = (Z_i.to_bytes(), proof_i)

    # 3. Test Pair {1, 2}
    resp_12 = {1: evals[1], 2: evals[2]}
    res_12 = client.process_threshold_evaluation_response(x, B, r, resp_12)
    assert isinstance(res_12, ThresholdEvaluationResult)
    assert res_12.token_bytes == baseline_token
    assert res_12 == baseline_token

    # 4. Test Pair {1, 3}
    resp_13 = {1: evals[1], 3: evals[3]}
    res_13 = client.process_threshold_evaluation_response(x, B, r, resp_13)
    assert res_13.token_bytes == baseline_token
    assert res_13 == baseline_token

    # 5. Test Pair {2, 3}
    resp_23 = {2: evals[2], 3: evals[3]}
    res_23 = client.process_threshold_evaluation_response(x, B, r, resp_23)
    assert res_23.token_bytes == baseline_token
    assert res_23 == baseline_token

    # Assert all pairs yield identical token
    assert res_12.token_bytes == res_13.token_bytes == res_23.token_bytes

def test_threshold_negative_single_response_rejected(threshold_keys):
    """
    Negative Test: Supplying only 1 party response (< 2) must be rejected fail-closed.
    """
    client = OANFarmerVOPRFClient(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        evaluator_public_key=threshold_keys["aggregate_K"],
        peer_public_keys=threshold_keys["peer_keys"]
    )
    x, B, r = client.prepare_blinded_registration("+254712345678")
    Z1, p1 = VOPRFEngine.evaluate(threshold_keys["shares"][1], B, threshold_keys["peer_keys"][1])

    with pytest.raises(CryptographicVerificationError, match="requires at least 2 distinct party responses"):
        client.process_threshold_evaluation_response(x, B, r, {1: (Z1.to_bytes(), p1)})

def test_threshold_negative_invalid_dleq_proof_rejected(threshold_keys):
    """
    Negative Test: If any participating party provides an invalid/tampered DLEQ proof,
    evaluation must fail closed immediately.
    """
    client = OANFarmerVOPRFClient(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        evaluator_public_key=threshold_keys["aggregate_K"],
        peer_public_keys=threshold_keys["peer_keys"]
    )
    x, B, r = client.prepare_blinded_registration("+254712345678")
    Z1, p1 = VOPRFEngine.evaluate(threshold_keys["shares"][1], B, threshold_keys["peer_keys"][1])
    Z2, p2 = VOPRFEngine.evaluate(threshold_keys["shares"][2], B, threshold_keys["peer_keys"][2])

    # Corrupt party 2's proof
    bad_p2 = bytes([p2[0] ^ 0xFF]) + p2[1:]

    with pytest.raises(CryptographicVerificationError, match="Evaluator DLEQ proof verification failed"):
        client.process_threshold_evaluation_response(
            x, B, r,
            {1: (Z1.to_bytes(), p1), 2: (Z2.to_bytes(), bad_p2)}
        )

def test_threshold_negative_duplicate_party_index_rejected(threshold_keys):
    """
    Negative Test: Duplicate party indices must be rejected fail-closed.
    """
    client = OANFarmerVOPRFClient(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        evaluator_public_key=threshold_keys["aggregate_K"],
        peer_public_keys=threshold_keys["peer_keys"]
    )
    x, B, r = client.prepare_blinded_registration("+254712345678")
    Z1, p1 = VOPRFEngine.evaluate(threshold_keys["shares"][1], B, threshold_keys["peer_keys"][1])

    # Pass duplicate entries for party index 1
    with pytest.raises(CryptographicVerificationError, match="Duplicate party indices"):
        client.process_threshold_evaluation_response(
            x, B, r,
            [(1, (Z1.to_bytes(), p1)), (1, (Z1.to_bytes(), p1))]
        )

def test_threshold_negative_aggregate_key_mismatch_rejected(threshold_keys):
    """
    Negative Test: If reconstructed K from participating parties does not match pinned
    evaluator_public_key, evaluation must fail closed.
    """
    wrong_pt = point_mul(99999999, GENERATOR_G.pt)
    client = OANFarmerVOPRFClient(
        pilot_id="kenya-pilot",
        key_id="ke-pilot-v4",
        evaluator_public_key=GroupElement(wrong_pt),
        peer_public_keys=threshold_keys["peer_keys"]
    )
    x, B, r = client.prepare_blinded_registration("+254712345678")
    Z1, p1 = VOPRFEngine.evaluate(threshold_keys["shares"][1], B, threshold_keys["peer_keys"][1])
    Z2, p2 = VOPRFEngine.evaluate(threshold_keys["shares"][2], B, threshold_keys["peer_keys"][2])

    with pytest.raises(CryptographicVerificationError, match="Reconstructed aggregate public key does not match pinned"):
        client.process_threshold_evaluation_response(
            x, B, r,
            {1: (Z1.to_bytes(), p1), 2: (Z2.to_bytes(), p2)}
        )
