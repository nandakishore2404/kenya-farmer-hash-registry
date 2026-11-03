import json
import uuid
import base64
import threading
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func

from app.main import app
from app.database import get_db
from app.config import settings
from app.models import Partner, PartnerEvaluationQuota
from app.crypto.voprf import VOPRFEngine
from app.routes.evaluator import EVALUATOR_KEY_ID
from sdk.python.hasher import sign_request
from tests.conftest import TestingSessionLocal

def test_concurrent_evaluations_respect_quota_without_overshoot(setup_test_db, monkeypatch):
    """
    Regression Test P1-2:
    With 10 remaining quota, launch 20 concurrent single-evaluation requests.
    Exactly 10 must succeed (HTTP 200) and exactly 10 must receive HTTP 429.
    Asserts zero quota overshoot in database state.
    """
    # 1. Configure quota to exactly 10
    monkeypatch.setattr(settings, "PARTNER_DAILY_QUOTA", 10)
    monkeypatch.setattr(settings, "PARTNER_QUOTA_WINDOW_HOURS", 24)

    # 2. Prepare valid blinded element
    phone = "+254712345678"
    x = VOPRFEngine.encode_input("kenya-pilot", phone)
    B, r = VOPRFEngine.blind(x)
    b_b64 = base64.b64encode(B.to_bytes()).decode("utf-8")

    api_key = "test_partner_a_api_key_2026"
    partner_id = "test_partner_a"

    # Dependency override for thread-safe database sessions
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    results = []
    errors = []

    try:
        with TestClient(app) as client:
            def make_eval_request(i):
                req_payload = {
                    "pilot_id": "kenya-pilot",
                    "key_id": EVALUATOR_KEY_ID,
                    "request_id": str(uuid.uuid4()),
                    "blinded_elements": [b_b64]
                }
                body = json.dumps(req_payload).encode("utf-8")
                headers = sign_request(
                    api_key=api_key,
                    method="POST",
                    path="/v1/evaluations",
                    query="",
                    body=body
                )
                headers["Content-Type"] = "application/json"
                try:
                    resp = client.post(
                        "/v1/evaluations",
                        content=body,
                        headers=headers
                    )
                    results.append((resp.status_code, resp.json()))
                except Exception as e:
                    errors.append(e)

            # Launch 20 concurrent requests
            threads = [threading.Thread(target=make_eval_request, args=(i,)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
    finally:
        app.dependency_overrides.pop(get_db, None)

    # Assertions
    assert len(errors) == 0, f"Encountered unexpected exceptions: {errors}"
    assert len(results) == 20, f"Expected 20 responses, got {len(results)}"

    status_200_count = sum(1 for code, _ in results if code == 200)
    status_429_count = sum(1 for code, _ in results if code == 429)

    assert status_200_count == 10, f"Expected exactly 10 HTTP 200s, got {status_200_count}"
    assert status_429_count == 10, f"Expected exactly 10 HTTP 429s, got {status_429_count}"

    # Verify database state has zero overshoot
    db = TestingSessionLocal()
    try:
        total_recorded_usage = db.query(
            func.coalesce(func.sum(PartnerEvaluationQuota.batch_size), 0)
        ).filter(
            PartnerEvaluationQuota.partner_id == partner_id
        ).scalar()

        assert total_recorded_usage == 10, (
            f"Atomic quota violation: expected exactly 10 recorded evaluations, but found {total_recorded_usage} (overshoot detected!)"
        )
    finally:
        db.close()
