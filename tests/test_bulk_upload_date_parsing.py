import requests
import pytest
from app.hashing import rekey_hash
from app.models import Farmer, PartnerLink
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "test_partner_a_api_key_2026"

def test_csv_upload_rejects_row_with_unreadable_date(client, db_session):
    """
    Test: CSV with one row dated 'not-a-date' and two valid rows:
    - received 3, accepted 2, rejected 1
    - Empty onboarded_at stays allowed and uses upload time
    - Does not include row content in any error message or log
    """
    p1 = "0791000001"
    p2 = "0791000002"
    p3 = "0791000003"
    h1 = hash_phone(p1, PARTNER_KEY)
    h2 = hash_phone(p2, PARTNER_KEY)
    h3 = hash_phone(p3, PARTNER_KEY)

    # Row 1: Valid date
    # Row 2: Unreadable date 'not-a-date'
    # Row 3: Empty date (allowed, uses upload time)
    csv_rows = [
        "hash,gender,age_band,county_code,onboarded_at",
        f"{h1},F,25-34,047,2026-10-02T10:00:00",
        f"{h2},M,35-44,032,not-a-date",
        f"{h3},F,18-24,019,",
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

    # Verify that valid rows h1 and h3 were stored in the database, while h2 was NOT stored
    r1 = rekey_hash(h1)
    r2 = rekey_hash(h2)
    r3 = rekey_hash(h3)

    assert db_session.query(Farmer).filter(Farmer.hash_key == r1).count() == 1
    assert db_session.query(Farmer).filter(Farmer.hash_key == r2).count() == 0, "Row with unreadable date must NOT be stored"
    assert db_session.query(Farmer).filter(Farmer.hash_key == r3).count() == 1, "Row with empty date must be stored"
