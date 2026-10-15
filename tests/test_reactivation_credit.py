import json
import pytest
from app.main import app
from app.database import get_db
from app.models import Farmer, PartnerLink
from app.hashing import rekey_hash
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "test_partner_a_api_key_2026"
BETA_KEY = "test_partner_b_api_key_2026"

def test_reactivation_credit_stays_with_continuous_partner(client, db_session):
    """
    Test: A registers -> B registers -> A withdraws (credit moves to B) -> A registers again -> credit stays with B.
    """
    phone = "0711998877"
    h = hash_phone(phone, PARTNER_KEY)
    rekeyed = rekey_hash(h)

    # 1. Partner A registers
    body_a = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode("utf-8")
    headers_a1 = sign_request(ALPHA_KEY, "POST", "/v1/farmers", "", body_a)
    headers_a1["Content-Type"] = "application/json"
    res1 = client.post("/v1/farmers", content=body_a, headers=headers_a1)
    assert res1.status_code == 200

    # 2. Partner B registers
    body_b = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:05:00Z"
    }).encode("utf-8")
    headers_b = sign_request(BETA_KEY, "POST", "/v1/farmers", "", body_b)
    headers_b["Content-Type"] = "application/json"
    res2 = client.post("/v1/farmers", content=body_b, headers=headers_b)
    assert res2.status_code == 200

    # 3. Partner A withdraws (credit moves to B)
    headers_del_a = sign_request(ALPHA_KEY, "DELETE", f"/v1/farmers/{h}", "", b"")
    res_del = client.delete(f"/v1/farmers/{h}", headers=headers_del_a)
    assert res_del.status_code == 200

    # Check Partner B's and Partner A's first_to_onboard before re-registration
    headers_sum_b1 = sign_request(BETA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_b1 = client.get("/v1/partners/me/summary", headers=headers_sum_b1)
    assert res_sum_b1.status_code == 200
    b_credit_before = res_sum_b1.json()["first_to_onboard"]

    headers_sum_a_before = sign_request(ALPHA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_a_before = client.get("/v1/partners/me/summary", headers=headers_sum_a_before)
    assert res_sum_a_before.status_code == 200
    a_credit_before = res_sum_a_before.json()["first_to_onboard"]

    # 4. Partner A registers the farmer again
    headers_a2 = sign_request(ALPHA_KEY, "POST", "/v1/farmers", "", body_a)
    headers_a2["Content-Type"] = "application/json"
    res3 = client.post("/v1/farmers", content=body_a, headers=headers_a2)
    assert res3.status_code == 200

    # Credit MUST stay with Partner B (first active registrant)
    headers_sum_b2 = sign_request(BETA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_b2 = client.get("/v1/partners/me/summary", headers=headers_sum_b2)
    assert res_sum_b2.status_code == 200
    assert res_sum_b2.json()["first_to_onboard"] == b_credit_before, "Credit should remain with Partner B who kept the active link"

    # Partner A should NOT reclaim first_to_onboard credit
    headers_sum_a = sign_request(ALPHA_KEY, "GET", "/v1/partners/me/summary", "", b"")
    res_sum_a = client.get("/v1/partners/me/summary", headers=headers_sum_a)
    assert res_sum_a.status_code == 200
    assert res_sum_a.json()["first_to_onboard"] == a_credit_before, "Partner A should not get first-to-onboard credit back"

    # Directly verify in DB that Partner B's link has an earlier received_at than Partner A's reactivated link
    farmer = db_session.query(Farmer).filter(Farmer.hash_key == rekeyed).first()
    assert farmer is not None
    link_a = db_session.query(PartnerLink).filter(PartnerLink.farmer_id == farmer.id, PartnerLink.partner_id == "test_partner_a").first()
    link_b = db_session.query(PartnerLink).filter(PartnerLink.farmer_id == farmer.id, PartnerLink.partner_id == "test_partner_b").first()
    assert link_b.received_at < link_a.received_at, "Partner B's received_at must be earlier than Partner A's reactivated received_at"
