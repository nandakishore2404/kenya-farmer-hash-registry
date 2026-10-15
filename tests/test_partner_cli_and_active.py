import json
import pytest
from app.models import Partner
from app.hashing import compute_request_signature, hash_api_key
from sdk.python.hasher import hash_phone

PARTNER_KEY = "partner_shared_pilot_secret"

def test_disabled_partner_rejected_with_401(client, db_session):
    # Disable test_partner_b
    partner_b = db_session.query(Partner).filter(Partner.partner_id == "test_partner_b").first()
    assert partner_b is not None
    partner_b.active = 0
    db_session.commit()
    
    h = hash_phone("0719999999", PARTNER_KEY)
    body = json.dumps({"hash": h, "gender": "F", "age_band": "25-34", "county_code": "047"}).encode()
    
    api_key_b = "test_partner_b_api_key_2026"
    sig = compute_request_signature(api_key_b, body)
    headers = {
        "X-Partner-Key": api_key_b,
        "X-Signature": sig,
        "Content-Type": "application/json"
    }
    
    res = client.post("/v1/farmers", content=body, headers=headers)
    assert res.status_code == 401
    assert "disabled" in res.text.lower()
    
    # Re-enable
    partner_b.active = 1
    db_session.commit()
