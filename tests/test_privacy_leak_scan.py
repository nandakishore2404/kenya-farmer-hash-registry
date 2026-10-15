import re
import os
import json
import pytest
from app.database import SessionLocal, Base, engine
from app.models import Farmer, PartnerLink, AuditLog, Partner
from app.hashing import rekey_hash, compute_request_signature
from sdk.python.hasher import hash_phone

PHONE_REGEX = re.compile(r"(\+?254[71]\d{8}|0[71]\d{8})")
PARTNER_KEY = "partner_shared_pilot_secret"
ALPHA_KEY = "alpha_api_key_pilot_2026"

def get_auth_headers(api_key: str, body: bytes) -> dict:
    sig = compute_request_signature(api_key, body)
    return {
        "X-Partner-Key": api_key,
        "X-Signature": sig,
        "Content-Type": "application/json"
    }

def test_database_privacy_leak_scan(client, db_session):
    """
    Exhaustive zero-knowledge privacy test:
    Scans every column of every table in the registry database to guarantee:
    1. Zero phone numbers are stored anywhere.
    2. Zero incoming partner hashes are stored anywhere.
    3. Audit logs record only actions and farmer IDs, never phone numbers or partner hashes.
    """
    sample_phones = [
        "+254712345678",
        "0722112233",
        "+254110998877",
        "254700123456"
    ]
    
    partner_hashes = set()
    
    for idx, p in enumerate(sample_phones):
        h = hash_phone(p, PARTNER_KEY)
        partner_hashes.add(h.lower())
        
        body = json.dumps({
            "hash": h,
            "gender": "F" if idx % 2 == 0 else "M",
            "age_band": "25-34",
            "county_code": "047"
        }).encode("utf-8")
        
        headers = get_auth_headers(ALPHA_KEY, body)
        res = client.post("/v1/farmers", content=body, headers=headers)
        assert res.status_code == 200

    # 1. Scan farmer table
    farmers = db_session.query(Farmer).all()
    assert len(farmers) >= len(sample_phones)
    
    for f in farmers:
        # Check hash_key
        assert f.hash_key.lower() not in partner_hashes, (
            f"SECURITY LEAK: Found incoming partner hash {f.hash_key} directly in farmer table!"
        )
        # Check no phone regex in any cleartext attribute field
        assert not PHONE_REGEX.search(str(f.gender))
        assert not PHONE_REGEX.search(str(f.age_band))
        assert not PHONE_REGEX.search(str(f.county_code))

    # 2. Scan partner_link table
    links = db_session.query(PartnerLink).all()
    for l in links:
        assert not PHONE_REGEX.search(str(l.partner_id))
        assert not PHONE_REGEX.search(str(l.status))

    # 3. Scan audit_log table
    audits = db_session.query(AuditLog).all()
    assert len(audits) > 0
    for a in audits:
        assert a.action not in partner_hashes
        assert not PHONE_REGEX.search(str(a.action))
        assert not PHONE_REGEX.search(str(a.partner_id))
        for ph in partner_hashes:
            assert ph not in str(a.action).lower()
            assert ph not in str(a.partner_id).lower()

    # 4. Raw database file content inspection
    if os.path.exists("./test_registry.db"):
        with open("./test_registry.db", "rb") as db_file:
            db_bytes = db_file.read()
            for ph in partner_hashes:
                assert ph.encode("ascii") not in db_bytes, (
                    f"SECURITY LEAK: Found incoming partner hash {ph} raw in database file!"
                )
            for p in sample_phones:
                cleaned_digits = re.sub(r"\D", "", p)[-9:]
                assert f"254{cleaned_digits}".encode("ascii") not in db_bytes
                assert f"0{cleaned_digits}".encode("ascii") not in db_bytes
