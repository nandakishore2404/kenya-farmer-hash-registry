import time
import json
import pytest
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "alpha_api_key_pilot_2026"

def test_signature_v2_and_replay_rejection(client):
    h = hash_phone("0719888777", PARTNER_KEY)
    payload = {
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T11:00:00Z"
    }
    body = json.dumps(payload).encode("utf-8")
    
    # 1. First request with valid signature v2 -> 200 OK
    headers = sign_request(
        api_key=ALPHA_KEY,
        method="POST",
        path="/v1/farmers",
        body=body
    )
    headers["Content-Type"] = "application/json"
    
    res1 = client.post("/v1/farmers", content=body, headers=headers)
    assert res1.status_code == 200
    assert res1.json() == {"status": "accepted"}
    
    # 2. Replay the EXACT same request (same nonce) -> 401 Unauthorized
    res_replay = client.post("/v1/farmers", content=body, headers=headers)
    assert res_replay.status_code == 401
    assert "replayed request" in res_replay.text.lower()
    
    # 3. Old timestamp (> 300 seconds ago) -> 401 Unauthorized
    old_headers = sign_request(
        api_key=ALPHA_KEY,
        method="POST",
        path="/v1/farmers",
        body=body,
        timestamp=int(time.time()) - 400
    )
    old_headers["Content-Type"] = "application/json"
    res_old = client.post("/v1/farmers", content=body, headers=old_headers)
    assert res_old.status_code == 401
    assert "expired" in res_old.text.lower()
    
    # 4. Signature made for one path/hash used on a different route/hash -> 401
    delete_headers = sign_request(
        api_key=ALPHA_KEY,
        method="DELETE",
        path=f"/v1/farmers/{h}",
        body=b""
    )
    # Tamper with path using another hash
    other_h = hash_phone("0719999000", PARTNER_KEY)
    res_tamper = client.delete(f"/v1/farmers/{other_h}", headers=delete_headers)
    assert res_tamper.status_code == 401
    assert "invalid request signature" in res_tamper.text.lower()
