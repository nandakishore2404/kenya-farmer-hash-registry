import json
import threading
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.database import get_db
from app.models import Farmer, TokenAlias, Partner
from app.hashing import rekey_hash
from sdk.python.hasher import sign_request
from tests.conftest import TestingSessionLocal

def test_concurrent_farmer_insert_on_duplicate_hash_key_returns_200(setup_test_db):
    """
    Regression Test P1-1:
    Asserts that 50 concurrent registrations of the exact same farmer incoming hash
    across multiple partner sessions complete with HTTP 200, zero 500 errors,
    and all resolve to the same underlying entity_id.
    """
    test_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
    payload = {
        "hash": test_hash,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047"
    }
    body = json.dumps(payload).encode("utf-8")

    partner_keys = [
        "test_partner_a_api_key_2026",
        "test_partner_b_api_key_2026",
        "test_partner_c_api_key_2026"
    ]

    results = []
    errors = []

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            def make_request(i):
                api_key = partner_keys[i % len(partner_keys)]
                headers = sign_request(api_key=api_key, method="POST", path="/v1/farmers", query="", body=body)
                headers["Content-Type"] = "application/json"
                try:
                    resp = client.post(
                        "/v1/farmers",
                        content=body,
                        headers=headers
                    )
                    results.append((resp.status_code, resp.json()))
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=make_request, args=(i,)) for i in range(50)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
    finally:
        app.dependency_overrides.pop(get_db, None)

    # Assertions
    assert len(errors) == 0, f"Encountered unexpected exceptions during concurrency: {errors}"
    assert len(results) == 50, f"Expected 50 responses, got {len(results)}"

    # All 50 threads must return HTTP 200 with status accepted
    entity_ids = set()
    for status_code, data in results:
        assert status_code == 200, f"Expected status 200, got {status_code}: {data}"
        assert data.get("status") == "accepted"
        entity_id = data.get("entity_id")
        assert entity_id is not None
        entity_ids.add(entity_id)

    # Exactly one unique entity_id shared across all 50 responses
    assert len(entity_ids) == 1, f"Expected exactly 1 common entity_id, found {entity_ids}"

    # Verify database consistency
    db = TestingSessionLocal()
    try:
        final_hash_key = rekey_hash(test_hash)
        farmers = db.query(Farmer).filter(Farmer.hash_key == final_hash_key).all()
        assert len(farmers) == 1, f"Expected exactly 1 Farmer record, found {len(farmers)}"

        aliases = db.query(TokenAlias).filter(TokenAlias.digest_d == final_hash_key).all()
        assert len(aliases) == 1, f"Expected exactly 1 TokenAlias record, found {len(aliases)}"

        resolved_entity_id = aliases[0].entity_id
        assert list(entity_ids)[0] == resolved_entity_id
        assert farmers[0].entity_id == resolved_entity_id
    finally:
        db.close()
