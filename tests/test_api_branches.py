import json
import requests
import pytest
from app.hashing import compute_request_signature, rekey_hash
from app.models import Farmer, PartnerLink, AuditLog
from sdk.python.hasher import hash_phone

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "alpha_api_key_pilot_2026"
BETA_KEY = "beta_api_key_pilot_2026"

def get_auth_headers(api_key: str, body: bytes, content_type: str = "application/json") -> dict:
    sig = compute_request_signature(api_key, body)
    headers = {
        "X-Partner-Key": api_key,
        "X-Signature": sig
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers

def test_auth_rejection(client):
    body = json.dumps({"hash": "a"*64, "gender": "F", "age_band": "25-34", "county_code": "047"}).encode()
    
    # 1. Missing headers -> 401
    res = client.post("/v1/farmers", content=body)
    assert res.status_code == 401
    
    # 2. Unknown partner key -> 401
    sig = compute_request_signature("fake_key", body)
    res = client.post("/v1/farmers", content=body, headers={"X-Partner-Key": "fake_key", "X-Signature": sig, "Content-Type": "application/json"})
    assert res.status_code == 401
    assert "Unknown or invalid" in res.text
    
    # 3. Bad signature -> 401
    res = client.post("/v1/farmers", content=body, headers={"X-Partner-Key": ALPHA_KEY, "X-Signature": "invalid_sig", "Content-Type": "application/json"})
    assert res.status_code == 401
    assert "Invalid request signature" in res.text


def test_farmer_registration_branches_and_idempotency(client, db_session):
    phone1 = "0712345678"
    hash1 = hash_phone(phone1, PARTNER_KEY)
    
    payload1 = {
        "hash": hash1,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047"
    }
    body1 = json.dumps(payload1).encode()
    
    # Branch 1: New farmer registered by Partner Alpha
    headers_alpha = get_auth_headers(ALPHA_KEY, body1)
    res1 = client.post("/v1/farmers", content=body1, headers=headers_alpha)
    assert res1.status_code == 200
    assert res1.json() == {"status": "accepted"}
    
    # Verify in DB
    links = db_session.query(PartnerLink).all()
    assert len(links) == 1
    assert links[0].partner_id == "partner_alpha"
    assert links[0].status == "active"
    
    # Branch 2: Idempotency (Partner Alpha sends the exact same farmer again)
    res2 = client.post("/v1/farmers", content=body1, headers=headers_alpha)
    assert res2.status_code == 200
    assert res2.json() == {"status": "accepted"}
    # No duplicate link created
    assert db_session.query(PartnerLink).count() == 1
    
    # Branch 3: Second Partner (Beta) onboards the SAME farmer
    # Identical response payload to ensure zero-knowledge cross-partner leakage
    headers_beta = get_auth_headers(BETA_KEY, body1)
    res3 = client.post("/v1/farmers", content=body1, headers=headers_beta)
    assert res3.status_code == 200
    assert res3.json() == {"status": "accepted"}
    
    # Both partners should now be linked to the single farmer
    farmers = db_session.query(Farmer).all()
    assert len(farmers) == 1
    links = db_session.query(PartnerLink).filter(PartnerLink.farmer_id == farmers[0].id).all()
    assert len(links) == 2
    partner_ids = {l.partner_id for l in links}
    assert partner_ids == {"partner_alpha", "partner_beta"}


def test_partner_summary_aggregates(client):
    # Partner Alpha summary
    body = b""
    headers_alpha = get_auth_headers(ALPHA_KEY, body, content_type=None)
    res = client.get("/v1/partners/me/summary", headers=headers_alpha)
    assert res.status_code == 200
    data = res.json()
    assert data["partner_id"] == "partner_alpha"
    assert data["farmers_sent"] == 1
    assert data["first_to_onboard"] == 1
    assert data["already_known"] == 0

    # Partner Beta summary
    headers_beta = get_auth_headers(BETA_KEY, body, content_type=None)
    res = client.get("/v1/partners/me/summary", headers=headers_beta)
    assert res.status_code == 200
    data_beta = res.json()
    assert data_beta["partner_id"] == "partner_beta"
    assert data_beta["farmers_sent"] == 1
    assert data_beta["first_to_onboard"] == 0
    assert data_beta["already_known"] == 1


def test_csv_upload_backfill(client, db_session):
    phone2 = "0722334455"
    phone3 = "0733445566"
    h2 = hash_phone(phone2, PARTNER_KEY)
    h3 = hash_phone(phone3, PARTNER_KEY)
    
    csv_data = f"""hash,gender,age_band,county_code,onboarded_at
{h2},M,35-44,032,2026-09-01T10:00:00
{h3},F,18-24,019,2026-09-02T11:00:00
invalid_hash_string,F,18-24,019,2026-09-02T11:00:00
"""
    file_bytes = csv_data.encode("utf-8")
    
    req = requests.Request("POST", "http://testserver/v1/farmers:upload", files={"file": ("farmers.csv", file_bytes, "text/csv")})
    prep = req.prepare()
    sig = compute_request_signature(ALPHA_KEY, prep.body)
    
    headers = {
        "X-Partner-Key": ALPHA_KEY,
        "X-Signature": sig,
        "Content-Type": prep.headers["Content-Type"]
    }
    res = client.post("/v1/farmers:upload", content=prep.body, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["rows_received"] == 2
    assert data["rows_rejected"] == 1


def test_consent_withdrawal_and_cascade(client, db_session):
    phone = "0712345678"
    h = hash_phone(phone, PARTNER_KEY)
    rekeyed = rekey_hash(h)
    
    # Currently farmer has 2 links: alpha and beta
    # Alpha withdraws consent
    headers_alpha = get_auth_headers(ALPHA_KEY, b"", content_type=None)
    res1 = client.delete(f"/v1/farmers/{h}", headers=headers_alpha)
    assert res1.status_code == 200
    assert res1.json() == {"status": "accepted"}
    
    # Farmer should still exist because Beta's link is still active
    f_after_alpha = db_session.query(Farmer).filter(Farmer.hash_key == rekeyed).first()
    assert f_after_alpha is not None
    
    # Beta withdraws consent
    headers_beta = get_auth_headers(BETA_KEY, b"", content_type=None)
    res2 = client.delete(f"/v1/farmers/{h}", headers=headers_beta)
    assert res2.status_code == 200
    
    # Now all active links are gone -> farmer record must be completely removed
    farmer = db_session.query(Farmer).filter(Farmer.hash_key == rekeyed).first()
    assert farmer is None


def test_admin_lookup(client):
    phone = "0722334455"  # uploaded in csv test
    h = hash_phone(phone, PARTNER_KEY)
    
    # Without admin key -> 403
    res_fail = client.get(f"/admin/lookup?hash={h}")
    assert res_fail.status_code == 403
    
    # With admin key -> 200
    res_ok = client.get(f"/admin/lookup?hash={h}", headers={"X-Admin-Key": "test_admin_key_super_secret"})
    assert res_ok.status_code == 200
    data = res_ok.json()
    assert "farmer_id" in data
    assert len(data["partners"]) >= 1


def test_dashboard_page(client):
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert "Kenya Agricultural Advisory Pilot" in res.text
    assert "Chart.js" in res.text or "chart.umd.min.js" in res.text
    assert "Unique Verified Farmers" in res.text
