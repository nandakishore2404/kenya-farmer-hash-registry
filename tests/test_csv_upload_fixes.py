import requests
import pytest
from app.hashing import rekey_hash
from app.models import Farmer, PartnerLink
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "test_partner_a_api_key_2026"

def test_csv_upload_duplicate_code_in_same_file(client, db_session):
    """
    Issue 1 reproduction test:
    When a CSV contains 10 valid distinct codes plus 1 repeated code:
    - All 11 distinct codes are stored
    - Exactly one partner_link is created per distinct code
    - Returned counts: rows_received=12, rows_accepted=12, rows_rejected=0
    """
    phones = [f"07123456{i:02d}" for i in range(11)]
    hashes = [hash_phone(p, PARTNER_KEY) for p in phones]
    
    # 11 distinct phones. Repeat the first hash at the end (total 12 rows).
    csv_rows = ["hash,gender,age_band,county_code,onboarded_at"]
    for h in hashes:
        csv_rows.append(f"{h},F,25-34,047,2026-10-02T10:00:00")
    csv_rows.append(f"{hashes[0]},F,25-34,047,2026-10-02T11:00:00")
    
    file_bytes = "\n".join(csv_rows).encode("utf-8")
    
    req = requests.Request("POST", "http://testserver/v1/farmers:upload", files={"file": ("farmers.csv", file_bytes, "text/csv")})
    prep = req.prepare()
    headers = sign_request(ALPHA_KEY, "POST", "/v1/farmers:upload", "", prep.body)
    headers["Content-Type"] = prep.headers["Content-Type"]
    
    res = client.post("/v1/farmers:upload", content=prep.body, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["rows_received"] == 12
    assert data["rows_accepted"] == 12
    assert data["rows_rejected"] == 0
    
    # Verify all 11 distinct farmers are stored with 1 link each
    rekeyed_hashes = [rekey_hash(h) for h in hashes]
    for rk in rekeyed_hashes:
        assert db_session.query(Farmer).filter(Farmer.hash_key == rk).count() == 1
        f = db_session.query(Farmer).filter(Farmer.hash_key == rk).first()
        assert db_session.query(PartnerLink).filter(PartnerLink.farmer_id == f.id, PartnerLink.partner_id == "test_partner_a").count() == 1


def test_csv_upload_invalid_row_isolation(client, db_session):
    """
    Issue 1 reproduction test:
    When a CSV contains an invalid row in the middle:
    - Every valid row before and after it is stored
    - Invalid row is rejected
    - Correct accepted and rejected counts
    """
    p1 = "0720000001"
    p2 = "0720000002"
    h1 = hash_phone(p1, PARTNER_KEY)
    h2 = hash_phone(p2, PARTNER_KEY)
    
    csv_rows = [
        "hash,gender,age_band,county_code,onboarded_at",
        f"{h1},F,25-34,047,2026-10-02T10:00:00",
        "invalid_not_64_hex,F,25-34,047,2026-10-02T10:00:00",
        f"{h2},M,35-44,032,2026-10-02T10:00:00",
    ]
    file_bytes = "\n".join(csv_rows).encode("utf-8")
    
    req = requests.Request("POST", "http://testserver/v1/farmers:upload", files={"file": ("farmers.csv", file_bytes, "text/csv")})
    prep = req.prepare()
    headers = sign_request(ALPHA_KEY, "POST", "/v1/farmers:upload", "", prep.body)
    headers["Content-Type"] = prep.headers["Content-Type"]
    
    res = client.post("/v1/farmers:upload", content=prep.body, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["rows_received"] == 3
    assert data["rows_accepted"] == 2
    assert data["rows_rejected"] == 1
    
    r1 = rekey_hash(h1)
    r2 = rekey_hash(h2)
    assert db_session.query(Farmer).filter(Farmer.hash_key == r1).count() == 1
    assert db_session.query(Farmer).filter(Farmer.hash_key == r2).count() == 1
