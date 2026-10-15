import os
import pytest
from app.config import Settings, COMMITTED_INSECURE_KEYS

def test_startup_fails_when_no_env_set_and_no_keys(monkeypatch):
    """
    With no ENV variable set and no keys provided, Settings() must default to production
    and refuse to start with a clear error.
    """
    monkeypatch.delenv("ENV", raising=False)
    monkeypatch.delenv("SERVER_KEY", raising=False)
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="Production configuration error: SERVER_KEY is required"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_startup_fails_with_env_example_placeholders(monkeypatch):
    """
    ENV=production loaded with .env.example placeholders (e.g. CHANGE_ME or committed insecure keys)
    must fail validation.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "CHANGE_ME")
    monkeypatch.setenv("ADMIN_KEY", "CHANGE_ME")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "CHANGE_ME")
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres:CHANGE_ME@db:5432/registry_db")

    with pytest.raises(ValueError, match="contains placeholder 'CHANGE_ME'|must be at least 32"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_startup_fails_with_dev_fallback_keys_in_production(monkeypatch):
    """
    ENV=production with development fallback keys must fail validation.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "dev_server_rekey_key_default_32_bytes_long!!")
    monkeypatch.setenv("ADMIN_KEY", "dev_admin_key_default_32_bytes_long_xyz!!")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "valid_long_dashboard_password_1234")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")

    with pytest.raises(ValueError, match="matches a known insecure committed placeholder"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_startup_fails_with_sqlite_in_production(monkeypatch):
    """
    Outside development, DATABASE_URL using SQLite must fail validation.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "valid_server_key_32_chars_long_1234567890123")
    monkeypatch.setenv("ADMIN_KEY", "valid_admin_key_32_chars_long_123456789012345")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "valid_long_dashboard_password_1234")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./registry.db")

    with pytest.raises(ValueError, match="SQLite cannot be used in production"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_startup_fails_with_seed_test_partners_in_production(monkeypatch):
    """
    Outside development, SEED_TEST_PARTNERS=True must fail validation.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "valid_server_key_32_chars_long_1234567890123")
    monkeypatch.setenv("ADMIN_KEY", "valid_admin_key_32_chars_long_123456789012345")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "valid_long_dashboard_password_1234")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "true")

    with pytest.raises(ValueError, match="SEED_TEST_PARTNERS must be False in production"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_startup_fails_with_short_dashboard_password_for_admin_in_production(monkeypatch):
    """
    Outside development, if DASHBOARD_USER='admin', DASHBOARD_PASSWORD shorter than 16 chars must fail.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "valid_server_key_32_chars_long_1234567890123")
    monkeypatch.setenv("ADMIN_KEY", "valid_admin_key_32_chars_long_123456789012345")
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "shortpass123")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "false")

    with pytest.raises(ValueError, match="DASHBOARD_PASSWORD must be at least 16 characters"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_production_starts_cleanly_with_secure_keys_and_postgres(monkeypatch):
    """
    ENV=production with secure generated keys and Postgres URL validates cleanly.
    """
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "c0ffee" * 8)  # 48 chars
    monkeypatch.setenv("ADMIN_KEY", "d099ee" * 8)   # 48 chars
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "a_very_secure_dashboard_pass_2026")
    monkeypatch.setenv("DATABASE_URL", "postgresql://prod_user:secret@localhost:5432/registry_db")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "false")

    s = Settings(_env_file=None)
    s.validate_production_security()
    assert s.ENV == "production"
    assert s.SERVER_KEY == "c0ffee" * 8

def test_production_dev_console_returns_404(client, monkeypatch):
    """
    When ENV=production, /dev/console returns 404.
    """
    from app.config import settings
    monkeypatch.setattr(settings, "ENV", "production")
    resp = client.get("/dev/console")
    assert resp.status_code == 404
