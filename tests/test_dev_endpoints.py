import json
import pytest
from app.config import settings
from app.models import Farmer, PartnerLink
from sdk.python.hasher import hash_phone, sign_request

PARTNER_KEY = "partner_shared_pilot_secret"
TEST_PARTNER_A_KEY = "test_partner_a_api_key_2026"

def test_requirements_versions_are_strictly_pinned():
    """
    requirements.txt must pin exact versions (==) without loose >= ranges.
    """
    with open("requirements.txt", "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    assert len(lines) > 0
    for line in lines:
        assert "==" in line, f"Dependency '{line}' in requirements.txt must be pinned with exact '=='"
        assert ">=" not in line, f"Dependency '{line}' in requirements.txt contains '>='"

def test_dev_console_and_unsuppressed_metrics(client, monkeypatch):
    """
    - GET /dev/console returns 200 when ENV=development
    - GET /dev/unsuppressed-metrics returns 200 after at least one registration and one withdrawal
    - Both must return 404 in production
    """
    # 1. When ENV=development
    monkeypatch.setattr(settings, "ENV", "development")
    res_console_dev = client.get("/dev/console")
    assert res_console_dev.status_code == 200
    assert "Test Console" in res_console_dev.text

    # Register farmer
    h = hash_phone("0719111222", PARTNER_KEY)
    body = json.dumps({
        "hash": h,
        "gender": "F",
        "age_band": "25-34",
        "county_code": "047",
        "onboarded_at": "2026-10-15T10:00:00Z"
    }).encode("utf-8")
    headers = sign_request(TEST_PARTNER_A_KEY, "POST", "/v1/farmers", body=body)
    headers["Content-Type"] = "application/json"
    res_reg_a = client.post("/v1/farmers", content=body, headers=headers)
    assert res_reg_a.status_code == 200

    TEST_PARTNER_B_KEY = "test_partner_b_api_key_2026"
    headers_b = sign_request(TEST_PARTNER_B_KEY, "POST", "/v1/farmers", body=body)
    headers_b["Content-Type"] = "application/json"
    res_reg_b = client.post("/v1/farmers", content=body, headers=headers_b)
    assert res_reg_b.status_code == 200

    # Withdraw farmer via Partner A
    del_headers = sign_request(TEST_PARTNER_A_KEY, "DELETE", f"/v1/farmers/{h}", body=b"")
    res_del = client.delete(f"/v1/farmers/{h}", headers=del_headers)
    assert res_del.status_code == 200

    # Dev unsuppressed-metrics
    res_metrics_dev = client.get("/dev/unsuppressed-metrics")
    assert res_metrics_dev.status_code == 200
    data = res_metrics_dev.json()
    assert data["total_removed_links"] >= 1
    assert "recent_links" in data

    # 2. When ENV=production -> Both return 404
    monkeypatch.setattr(settings, "ENV", "production")
    res_console_prod = client.get("/dev/console")
    assert res_console_prod.status_code == 404

    res_metrics_prod = client.get("/dev/unsuppressed-metrics")
    assert res_metrics_prod.status_code == 404

def test_reset_db_script_reports_accurate_status(monkeypatch, capsys):
    """
    scripts/reset_db.py must print what actually happened rather than unconditionally
    claiming partners were seeded.
    """
    from scripts.reset_db import reset_local_db

    # In development with SEED_TEST_PARTNERS=True
    monkeypatch.setattr(settings, "ENV", "development")
    monkeypatch.setattr(settings, "SEED_TEST_PARTNERS", True)
    reset_local_db()
    captured = capsys.readouterr()
    assert "Seeded 3 partners: Test Partner A, Test Partner B, Test Partner C" in captured.out

    # In development with SEED_TEST_PARTNERS=False
    monkeypatch.setattr(settings, "SEED_TEST_PARTNERS", False)
    from app.database import Base, engine
    Base.metadata.drop_all(bind=engine)
    reset_local_db()
    captured2 = capsys.readouterr()
    assert "No partners seeded" in captured2.out
