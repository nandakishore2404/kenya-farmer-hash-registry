import hmac
import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.database import get_db, Base, engine
from app.models import Partner, Farmer, PartnerLink, RequestNonce
from app.hashing import hash_api_key, rekey_hash

client = TestClient(app)

PARTNER_KEY = "test_partner_a_api_key_2026"
PARTNER_ID = "test_partner_a"

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        # Ensure test partner exists
        partner = db.query(Partner).filter(Partner.partner_id == PARTNER_ID).first()
        if not partner:
            partner = Partner(
                partner_id=PARTNER_ID,
                name="Test Partner A",
                api_key_hash=hash_api_key(PARTNER_KEY),
                active=1
            )
            db.add(partner)
            db.commit()
    finally:
        db.close()

def compute_v1_sig(key: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()

def test_post_with_body_only_signature_is_rejected():
    """
    POST with only X-Partner-Key and a body-only X-Signature (missing X-Timestamp and X-Nonce)
    must be rejected with 401 'Missing signature headers'.
    """
    body = json.dumps({
        "hash": "a" * 64,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode("utf-8")
    sig = compute_v1_sig(PARTNER_KEY, body)

    headers = {
        "X-Partner-Key": PARTNER_KEY,
        "X-Signature": sig,
        "Content-Type": "application/json"
    }

    resp = client.post("/v1/farmers", content=body, headers=headers)
    assert resp.status_code == 401
    assert "Missing signature headers" in resp.json().get("detail", "")

def test_delete_with_empty_body_v1_signature_is_rejected():
    """
    DELETE with an empty-body v1 signature HMAC(key, "") must be rejected with 401,
    and the farmer link must remain intact in the database.
    """
    # First, register farmer properly
    from sdk.python.hasher import sign_request
    h = "b" * 64
    body = json.dumps({
        "hash": h,
        "gender": "M",
        "age_band": "35-44",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode("utf-8")
    headers = sign_request(PARTNER_KEY, "POST", "/v1/farmers", "", body)
    headers["Content-Type"] = "application/json"
    reg_resp = client.post("/v1/farmers", content=body, headers=headers)
    assert reg_resp.status_code == 200

    # Verify farmer link exists
    db = next(get_db())
    farmer = db.query(Farmer).filter(Farmer.hash_key == rekey_hash(h)).first()
    assert farmer is not None
    link = db.query(PartnerLink).filter(PartnerLink.farmer_id == farmer.id, PartnerLink.partner_id == PARTNER_ID).first()
    assert link is not None and link.status == "active"
    db.close()

    # Now attempt DELETE using v1 empty-body signature (missing X-Timestamp and X-Nonce)
    empty_v1_sig = compute_v1_sig(PARTNER_KEY, b"")
    del_headers = {
        "X-Partner-Key": PARTNER_KEY,
        "X-Signature": empty_v1_sig
    }
    del_resp = client.delete(f"/v1/farmers/{h}", headers=del_headers)
    assert del_resp.status_code == 401
    assert "Missing signature headers" in del_resp.json().get("detail", "")

    # Verify farmer link was NOT removed
    db = next(get_db())
    link_after = db.query(PartnerLink).filter(PartnerLink.farmer_id == farmer.id, PartnerLink.partner_id == PARTNER_ID).first()
    assert link_after is not None and link_after.status == "active"
    db.close()

def test_bad_signature_with_fresh_nonce_does_not_store_nonce():
    """
    A request with a bad signature and a fresh nonce must return 401,
    and no row must be added to request_nonce.
    """
    import time
    fresh_nonce = "fresh_nonce_1234567890_test"
    ts = str(int(time.time()))
    body = json.dumps({
        "hash": "c" * 64,
        "gender": "F",
        "age_band": "18-24",
        "county_code": "001",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode("utf-8")

    db = next(get_db())
    # Ensure nonce not already present
    db.query(RequestNonce).filter(RequestNonce.nonce == fresh_nonce).delete()
    db.commit()
    db.close()

    headers = {
        "X-Partner-Key": PARTNER_KEY,
        "X-Timestamp": ts,
        "X-Nonce": fresh_nonce,
        "X-Signature": "invalid_bad_signature_value_12345",
        "Content-Type": "application/json"
    }

    resp = client.post("/v1/farmers", content=body, headers=headers)
    assert resp.status_code == 401
    assert "Invalid request signature" in resp.json().get("detail", "")

    # Verify nonce was NOT stored in the database
    db = next(get_db())
    stored_nonce = db.query(RequestNonce).filter(RequestNonce.nonce == fresh_nonce).first()
    assert stored_nonce is None, "Nonce should NOT be recorded when signature verification fails"
    db.close()
