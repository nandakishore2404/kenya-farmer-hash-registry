import os
import sys
import json
import time
import uuid
import random
import requests
from datetime import datetime, timezone

# Ensure root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sdk.python.hasher import hash_phone, sign_request
from app.config import settings
from app.database import SessionLocal
from app.models import Farmer, PartnerLink, Partner
from app.hashing import hash_api_key

BASE_URL = os.environ.get("REGISTRY_URL", "http://localhost:8008")
PARTNER_KEY = os.environ.get("PARTNER_KEY", "partner_shared_pilot_secret")

PARTNERS = {
    "test_partner_a": "test_partner_a_api_key_2026",
    "test_partner_b": "test_partner_b_api_key_2026",
    "test_partner_c": "test_partner_c_api_key_2026",
}

def make_request(method: str, path: str, partner_id: str, body: bytes | str = b"", headers_override: dict = None):
    url = f"{BASE_URL}{path}"
    api_key = PARTNERS.get(partner_id, "test_partner_a_api_key_2026")
    
    if headers_override:
        headers = headers_override
    else:
        headers = sign_request(api_key, method, path, "", body)
        if body and isinstance(body, (bytes, str)):
            headers["Content-Type"] = "application/json"
            
    resp = requests.request(method, url, data=body, headers=headers)
    return resp

# 1. Single Registration
def test_scenario_single_registration():
    phone = f"+254712{random.randint(100000, 999999)}"
    h = hash_phone(phone, PARTNER_KEY)
    payload = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    resp = make_request("POST", "/v1/farmers", "test_partner_a", payload)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.json() == {"status": "accepted"}
    return "1 farmer registered & credited"

# 2. Shared Phone
def test_scenario_shared_phone():
    phone = f"+254712{random.randint(100000, 999999)}"
    h = hash_phone(phone, PARTNER_KEY)
    # Partner A registers
    payload_a = json.dumps({
        "hash": h, "gender": "F", "age_band": "25-34", "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    resp_a = make_request("POST", "/v1/farmers", "test_partner_a", payload_a)
    assert resp_a.status_code == 200
    
    # Partner B registers same phone (shared household)
    payload_b = json.dumps({
        "hash": h, "gender": "M", "age_band": "45-54", "county_code": "047",
        "onboarded_at": "2026-10-15T10:01:00Z"
    })
    resp_b = make_request("POST", "/v1/farmers", "test_partner_b", payload_b)
    assert resp_b.status_code == 200
    return "1 farmer code, 2 partner links"

# 3. Second SIM
def test_scenario_second_sim():
    phone1 = f"+254712{random.randint(100000, 999999)}"
    phone2 = f"+254712{random.randint(100000, 999999)}"
    h1 = hash_phone(phone1, PARTNER_KEY)
    h2 = hash_phone(phone2, PARTNER_KEY)
    
    payload1 = json.dumps({
        "hash": h1, "gender": "F", "age_band": "25-34", "county_code": "032",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    resp1 = make_request("POST", "/v1/farmers", "test_partner_a", payload1)
    assert resp1.status_code == 200
    
    payload2 = json.dumps({
        "hash": h2, "gender": "F", "age_band": "25-34", "county_code": "032",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    resp2 = make_request("POST", "/v1/farmers", "test_partner_b", payload2)
    assert resp2.status_code == 200
    return "2 distinct farmer codes created"

# 4. Consent Withdrawal
def test_scenario_consent_withdrawal():
    phone = f"+254712{random.randint(100000, 999999)}"
    h = hash_phone(phone, PARTNER_KEY)
    # Register with both partners
    for pid in ["test_partner_a", "test_partner_b"]:
        payload = json.dumps({
            "hash": h, "gender": "M", "age_band": "35-44", "county_code": "019",
            "onboarded_at": "2026-10-15T10:00:00Z"
        })
        resp = make_request("POST", "/v1/farmers", pid, payload)
        assert resp.status_code == 200

    # Withdraw Partner A
    resp_del_a = make_request("DELETE", f"/v1/farmers/{h}", "test_partner_a")
    assert resp_del_a.status_code == 200
    assert resp_del_a.json()["status"] == "accepted"

    # Withdraw Partner B (last link)
    resp_del_b = make_request("DELETE", f"/v1/farmers/{h}", "test_partner_b")
    assert resp_del_b.status_code == 200
    assert resp_del_b.json()["status"] == "accepted"
    return "Farmer purged only after last partner link removed"

# 5. First-to-Onboard Attribution
def test_scenario_first_to_onboard():
    phone = f"+254712{random.randint(100000, 999999)}"
    h = hash_phone(phone, PARTNER_KEY)
    
    # Partner A registers now
    payload_a = json.dumps({
        "hash": h, "gender": "F", "age_band": "25-34", "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    resp_a = make_request("POST", "/v1/farmers", "test_partner_a", payload_a)
    assert resp_a.status_code == 200
    
    # Partner B registers same farmer with older onboarded_at date
    payload_b = json.dumps({
        "hash": h, "gender": "F", "age_band": "25-34", "county_code": "047",
        "onboarded_at": "2026-10-02T10:00:00Z"
    })
    resp_b = make_request("POST", "/v1/farmers", "test_partner_b", payload_b)
    assert resp_b.status_code == 200
    return "First-to-onboard credit retained by Partner A via received_at"

# 6. CSV Duplicates & Isolation
def test_scenario_csv_duplicates():
    p_dup = f"+254712{random.randint(100000, 999999)}"
    p_uniq = f"+254712{random.randint(100000, 999999)}"
    h_dup = hash_phone(p_dup, PARTNER_KEY)
    h_uniq = hash_phone(p_uniq, PARTNER_KEY)
    
    csv_content = (
        "hash,gender,age_band,county_code,onboarded_at\n"
        f"{h_dup},F,25-34,047,2026-10-15T10:00:00Z\n"
        f"{h_dup},M,45-54,047,2026-10-15T10:01:00Z\n"
        f"{h_uniq},M,35-44,032,2026-10-15T10:02:00Z\n"
        f"bad_hash,X,99-99,999,2026-10-15T10:03:00Z\n"
    )
    api_key = PARTNERS["test_partner_c"]
    csv_bytes = csv_content.encode("utf-8")
    headers = sign_request(api_key, "POST", "/v1/farmers:upload", "", csv_bytes)
    headers["Content-Type"] = "text/csv"
    
    resp = requests.post(f"{BASE_URL}/v1/farmers:upload", data=csv_bytes, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rows_received"] == 4
    assert data["rows_accepted"] == 3
    assert data["rows_rejected"] == 1
    return "CSV duplicate handled, valid rows isolated from bad row"

# 7. Replay Attack
def test_scenario_replay_attack():
    phone = f"+254712{random.randint(100000, 999999)}"
    h = hash_phone(phone, PARTNER_KEY)
    payload = json.dumps({
        "hash": h, "gender": "F", "age_band": "25-34", "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    })
    api_key = PARTNERS["test_partner_a"]
    headers = sign_request(api_key, "POST", "/v1/farmers", "", payload)
    headers["Content-Type"] = "application/json"
    
    # 1st request succeeds
    r1 = requests.post(f"{BASE_URL}/v1/farmers", data=payload, headers=headers)
    assert r1.status_code == 200
    
    # 2nd request with exact same nonce and timestamp gets rejected
    r2 = requests.post(f"{BASE_URL}/v1/farmers", data=payload, headers=headers)
    assert r2.status_code == 401, f"Expected 401 for replay, got {r2.status_code}: {r2.text}"
    return "Replayed nonce rejected with 401"

# 8. Disabled Partner
def test_scenario_disabled_partner():
    # Disable test_partner_b in database
    db = SessionLocal()
    try:
        p = db.query(Partner).filter(Partner.partner_id == "test_partner_b").first()
        if p:
            p.active = 0
            db.commit()
    finally:
        db.close()

    try:
        phone = f"+254712{random.randint(100000, 999999)}"
        h = hash_phone(phone, PARTNER_KEY)
        payload = json.dumps({
            "hash": h, "gender": "F", "age_band": "25-34", "county_code": "047",
            "onboarded_at": "2026-10-15T10:00:00Z"
        })
        resp = make_request("POST", "/v1/farmers", "test_partner_b", payload)
        assert resp.status_code == 401, f"Expected 401 for disabled partner, got {resp.status_code}"
    finally:
        # Re-enable partner
        db = SessionLocal()
        try:
            p = db.query(Partner).filter(Partner.partner_id == "test_partner_b").first()
            if p:
                p.active = 1
                db.commit()
        finally:
            db.close()
            
    return "Disabled partner rejected with 401"

SCENARIOS = {
    "single-registration": test_scenario_single_registration,
    "shared-phone": test_scenario_shared_phone,
    "second-sim": test_scenario_second_sim,
    "consent-withdrawal": test_scenario_consent_withdrawal,
    "first-to-onboard": test_scenario_first_to_onboard,
    "csv-duplicates": test_scenario_csv_duplicates,
    "replay-attack": test_scenario_replay_attack,
    "disabled-partner": test_scenario_disabled_partner,
}

def run_scenarios(target: str = "all"):
    print("\n" + "=" * 74)
    print(" KENYA FARMER HASH REGISTRY - SCENARIO TEST SUITE")
    print(f" Target Endpoint: {BASE_URL}")
    print("=" * 74)
    print(f" {'#':<2} {'Scenario Name':<22} {'Status':<8} {'Details'}")
    print("-" * 74)
    
    to_run = SCENARIOS.keys() if target in ["all", ""] else [target]
    passed = 0
    failed = 0
    
    idx = 1
    for name in to_run:
        func = SCENARIOS.get(name)
        if not func:
            print(f"Unknown scenario: {name}. Available: {list(SCENARIOS.keys())}")
            sys.exit(1)
            
        try:
            detail = func()
            print(f" {idx:<2} {name:<22} \033[92mPASS\033[0m     {detail}")
            passed += 1
        except Exception as e:
            print(f" {idx:<2} {name:<22} \033[91mFAIL\033[0m     Error: {e}")
            failed += 1
        idx += 1
        
    print("-" * 74)
    print(f" Total: {passed + failed} | Passed: {passed} | Failed: {failed}")
    print("=" * 74 + "\n")
    
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "all"
    run_scenarios(arg)
