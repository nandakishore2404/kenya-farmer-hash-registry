import pytest
import base64
from app.config import settings

def test_dashboard_without_auth_returns_401(client):
    res = client.get("/dashboard")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers

def test_dashboard_with_invalid_credentials_returns_401(client):
    token = base64.b64encode(b"wronguser:wrongpass").decode("ascii")
    headers = {"Authorization": f"Basic {token}"}
    res = client.get("/dashboard", headers=headers)
    assert res.status_code == 401

def test_dashboard_with_correct_credentials_returns_200(client):
    user = settings.DASHBOARD_USER
    pwd = settings.DASHBOARD_PASSWORD.get_secret_value() if hasattr(settings.DASHBOARD_PASSWORD, "get_secret_value") else str(settings.DASHBOARD_PASSWORD)
    token = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
    headers = {"Authorization": f"Basic {token}"}
    res = client.get("/dashboard", headers=headers)
    assert res.status_code == 200
    assert "Unique Verified Farmers" in res.text
