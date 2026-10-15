import pytest
import os
from app.config import Settings, COMMITTED_INSECURE_KEYS

def test_production_missing_server_key_raises_error(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "")
    monkeypatch.setenv("ADMIN_KEY", "a"*32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "strong_password_123")
    
    with pytest.raises(ValueError, match="SERVER_KEY is required"):
        s = Settings(SERVER_KEY="")
        s.validate_production_security()

def test_production_short_server_key_raises_error(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "too_short")
    monkeypatch.setenv("ADMIN_KEY", "a"*32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "strong_password_123")
    
    with pytest.raises(ValueError, match="SERVER_KEY must be at least 32 characters"):
        s = Settings()
        s.validate_production_security()

def test_production_committed_placeholder_key_raises_error(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "prod_server_secret_rekey_key_9876543210")
    monkeypatch.setenv("ADMIN_KEY", "a"*32)
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "strong_password_123")
    
    with pytest.raises(ValueError, match="matches a known insecure committed placeholder"):
        s = Settings()
        s.validate_production_security()

def test_production_valid_keys_succeeds(monkeypatch):
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "secure_server_key_0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("ADMIN_KEY", "secure_admin_key_0123456789abcdef0123456789abcdef")
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres:pass@localhost:5432/db")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "dashboard_secure_pass_123")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "false")
    
    s = Settings()
    s.validate_production_security()
    assert s.SERVER_KEY == "secure_server_key_0123456789abcdef0123456789abcdef"
