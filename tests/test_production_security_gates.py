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
    import secrets
    import base64
    from app.crypto.voprf import N_ORDER, GENERATOR_G, point_mul, GroupElement
    k = secrets.randbelow(N_ORDER - 1) + 1
    K_pt = point_mul(k, GENERATOR_G.pt)
    K_b64 = base64.b64encode(GroupElement(K_pt).to_bytes()).decode()

    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "c0ffee" * 8)  # 48 chars
    monkeypatch.setenv("ADMIN_KEY", "d099ee" * 8)   # 48 chars
    monkeypatch.setenv("DASHBOARD_USER", "admin")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "a_very_secure_dashboard_pass_2026")
    monkeypatch.setenv("DATABASE_URL", "postgresql://prod_user:secret@localhost:5432/registry_db")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "false")
    monkeypatch.setenv("EVALUATOR_SHARE_K", f"{k:064x}")
    monkeypatch.setenv("EVALUATOR_PEER_PUBKEYS", f"{K_b64},{K_b64},{K_b64}")
    monkeypatch.setenv("EVALUATOR_AGGREGATE_PUB", K_b64)

    s = Settings(_env_file=None)
    s.validate_production_security()
    assert s.ENV == "production"
    assert s.SERVER_KEY == "c0ffee" * 8

def test_absent_share_refuses_production_boot(monkeypatch):
    """
    With ENV=production and no EVALUATOR_SHARE_K, importing config or the evaluator router raises.
    """
    orig_share = os.environ.get("EVALUATOR_SHARE_K")
    import app.routes.evaluator
    orig_settings_share = getattr(app.routes.evaluator.settings, "EVALUATOR_SHARE_K", None)

    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("SERVER_KEY", "c0ffee" * 8)
    monkeypatch.setenv("ADMIN_KEY", "d099ee" * 8)
    monkeypatch.setenv("DASHBOARD_PASSWORD", "a_very_secure_dashboard_pass_2026")
    monkeypatch.setenv("DATABASE_URL", "postgresql://prod_user:secret@localhost:5432/registry_db")
    monkeypatch.setenv("SEED_TEST_PARTNERS", "false")
    monkeypatch.delenv("EVALUATOR_SHARE_K", raising=False)
    monkeypatch.setattr(app.routes.evaluator.settings, "EVALUATOR_SHARE_K", None)

    with pytest.raises(ValueError, match="EVALUATOR_SHARE_K is required"):
        s = Settings(_env_file=None)
        s.validate_production_security()

    import importlib
    try:
        with pytest.raises(RuntimeError, match="EVALUATOR_SHARE_K is not set or is empty"):
            importlib.reload(app.routes.evaluator)
    finally:
        monkeypatch.undo()
        if orig_share:
            os.environ["EVALUATOR_SHARE_K"] = orig_share
        if orig_settings_share:
            setattr(app.routes.evaluator.settings, "EVALUATOR_SHARE_K", orig_settings_share)
        importlib.reload(app.routes.evaluator)

def test_retired_literal_rejected_as_burned(monkeypatch):
    """
    Asserts that the retired evaluator share literal is permanently burned and refused.
    """
    retired_hex = "5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8"
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("EVALUATOR_SHARE_K", retired_hex)

    with pytest.raises(ValueError, match="matches a known burned"):
        s = Settings(_env_file=None)
        s.validate_production_security()

def test_production_dev_console_returns_404(client, monkeypatch):
    """
    When ENV=production, /dev/console returns 404.
    """
    from app.config import settings
    monkeypatch.setattr(settings, "ENV", "production")
    resp = client.get("/dev/console")
    assert resp.status_code == 404


def test_env_normalization_case_insensitive_enforces_production(monkeypatch):
    """
    Finding A-1: Assert that casing variations like 'Production', 'PRODUCTION', ' production '
    are strictly normalized and enforce production security gates fail-closed.
    """
    for env_val in ["Production", "PRODUCTION", " production ", "  ProDuCtIoN  "]:
        monkeypatch.setenv("ENV", env_val)
        monkeypatch.delenv("SERVER_KEY", raising=False)
        with pytest.raises(ValueError, match="SERVER_KEY is required"):
            s = Settings(_env_file=None)
            s.validate_production_security()

def test_invalid_env_rejected():
    """
    Invalid ENV values (e.g. 'prod', 'testing', random strings) must be rejected fail-closed.
    """
    with pytest.raises(ValueError, match="Invalid ENV"):
        Settings(ENV="invalid_env", _env_file=None)

def test_server_key_fail_closed_in_hashing(monkeypatch):
    """
    Finding A-1: Assert that SERVER_KEY=None, empty, or 'None' strictly raises RuntimeError
    in rekey_hash and compute_voprf_storage_digest, preventing b'None' HMAC zero-knowledge breach.
    """
    from app.config import settings
    from app.hashing import rekey_hash, compute_voprf_storage_digest

    monkeypatch.setattr(settings, "SERVER_KEY", None)
    with pytest.raises(RuntimeError, match="FATAL: SERVER_KEY is not configured"):
        rekey_hash("abcdef1234567890")

    with pytest.raises(RuntimeError, match="FATAL: SERVER_KEY is not configured"):
        compute_voprf_storage_digest("pilot", "v4", b"\x01" * 64)

    monkeypatch.setattr(settings, "SERVER_KEY", "None")
    with pytest.raises(RuntimeError, match="FATAL: SERVER_KEY is empty or invalid"):
        rekey_hash("abcdef1234567890")

def test_test_share_literal_burned(monkeypatch):
    """
    Finding A-2: Assert that the test share literal 9fe8ad... is burned and rejected in all environments.
    """
    burned_test_share = "9fe8ad784aa9c596b091060eeaf91ef3330eae2954251a91018aa76699983a85"
    monkeypatch.setenv("ENV", "development")
    monkeypatch.setenv("EVALUATOR_SHARE_K", burned_test_share)
    with pytest.raises(ValueError, match="matches a known burned"):
        Settings(_env_file=None)
