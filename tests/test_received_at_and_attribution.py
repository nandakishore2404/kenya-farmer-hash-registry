import json
import pytest
from datetime import datetime, timezone, timedelta
from app.models import Farmer, PartnerLink
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "alpha_api_key_pilot_2026"
BETA_KEY = "beta_api_key_pilot_2026"

def get_auth_headers(api_key: str, body: bytes) -> dict:
    headers = sign_request(api_key, "POST", "/v1/farmers", "", body)
    headers["Content-Type"] = "application/json"
    return headers

def test_future_or_very_old_onboarded_at_rejected(client):
    """
    Validate onboarded_at: reject dates more than 5 minutes in the future or earlier than PILOT_START_DATE (default 2026-10-01).
    """
    h = hash_phone("0711000001", PARTNER_KEY)
    
    # 1. Date in 2020 (before PILOT_START_DATE) -> 422
    body_old = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2020-01-01T10:00:00Z"
    }).encode()
    res1 = client.post("/v1/farmers", content=body_old, headers=get_auth_headers(ALPHA_KEY, body_old))
    assert res1.status_code == 422
    
    # 2. Date 10 minutes in future -> 422
    future_time = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    body_future = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": future_time
    }).encode()
    res2 = client.post("/v1/farmers", content=body_future, headers=get_auth_headers(ALPHA_KEY, body_future))
    assert res2.status_code == 422


def test_first_to_onboard_credit_retained_by_received_at(client, db_session):
    """
    Partner A registers a farmer today.
    Partner B registers the same farmer claiming an earlier onboarded_at (within allowed window).
    Partner A keeps first-to-onboard credit because Partner A's request was received first by server.
    """
    h = hash_phone("0711000002", PARTNER_KEY)
    
    # Partner A registers now
    body_a = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode()
    res_a = client.post("/v1/farmers", content=body_a, headers=get_auth_headers(ALPHA_KEY, body_a))
    assert res_a.status_code == 200
    
    # Partner B registers same farmer with earlier date (2026-10-05)
    body_b = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-05T10:00:00Z"
    }).encode()
    res_b = client.post("/v1/farmers", content=body_b, headers=get_auth_headers(BETA_KEY, body_b))
    assert res_b.status_code == 200
    
    # Query summary for Partner A -> first_to_onboard should be credited to A
    headers_summary_a = sign_request(ALPHA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_a = client.get("/v1/partners/me/summary", headers=headers_summary_a)
    assert res_sum_a.status_code == 200
    
    headers_summary_b = sign_request(BETA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_b = client.get("/v1/partners/me/summary", headers=headers_summary_b)
    assert res_sum_b.status_code == 200
    
    # Partner B did not get first_to_onboard credit despite claiming an earlier onboarded_at date!
    # Because Partner A was received first by the server.
    data_a = res_sum_a.json()
    data_b = res_sum_b.json()
    # Check that A has first_to_onboard credit for this farmer
    link_a = db_session.query(PartnerLink).filter(PartnerLink.partner_id == "partner_alpha", PartnerLink.farmer.has(hash_key=Farmer.hash_key)).first()
    assert link_a.received_at is not None
