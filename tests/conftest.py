import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Purge deprecated single-key environment variable
os.environ.pop("EVALUATOR_SECRET_K", None)

# Set test environment variables before importing app modules
os.environ["ENV"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///./test_registry.db"
os.environ["SERVER_KEY"] = "test_server_secret_rekey_key_abc123"
os.environ["ADMIN_KEY"] = "test_admin_key_super_secret"
os.environ["EVALUATOR_KEY_ID"] = "ke-pilot-v4"
os.environ["EVALUATOR_PARTY_ID"] = "safic"
os.environ["EVALUATOR_PARTY_INDEX"] = "1"
import base64
import secrets
from app.crypto.voprf import N_ORDER, GENERATOR_G, point_mul, GroupElement

# Ephemeral dynamic 2-of-3 Shamir test key generation
_test_k = secrets.randbelow(N_ORDER - 1) + 1
_test_a = secrets.randbelow(N_ORDER - 1) + 1
_test_s1 = (_test_k + _test_a * 1) % N_ORDER
_test_s2 = (_test_k + _test_a * 2) % N_ORDER
_test_s3 = (_test_k + _test_a * 3) % N_ORDER

_test_K = GroupElement(point_mul(_test_k, GENERATOR_G.pt))
_test_K1 = GroupElement(point_mul(_test_s1, GENERATOR_G.pt))
_test_K2 = GroupElement(point_mul(_test_s2, GENERATOR_G.pt))
_test_K3 = GroupElement(point_mul(_test_s3, GENERATOR_G.pt))

os.environ["EVALUATOR_SHARE_K"] = f"{_test_s1:064x}"
os.environ["EVALUATOR_PEER_PUBKEYS"] = f"{base64.b64encode(_test_K1.to_bytes()).decode()},{base64.b64encode(_test_K2.to_bytes()).decode()},{base64.b64encode(_test_K3.to_bytes()).decode()}"
os.environ["EVALUATOR_AGGREGATE_PUB"] = base64.b64encode(_test_K.to_bytes()).decode()
os.environ["CURVE_BACKEND"] = "pure_python"

from app.config import settings
from app.database import Base, get_db
from app.main import app, TEST_PARTNERS
from app.models import Partner
from app.hashing import hash_api_key

TEST_DB_URL = "sqlite:///./test_registry.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="function", autouse=True)
def setup_test_db():
    """
    Per-test database isolation fixture.
    Drops and recreates all tables per test function, seeding fresh test partners.
    Prevents cross-test state leakage, duplicate nonces, and SQLite lock contention.
    """
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    # Pre-seed neutral test partners
    db = TestingSessionLocal()
    for p in TEST_PARTNERS:
        db.add(Partner(
            partner_id=p["partner_id"],
            name=p["name"],
            api_key_hash=hash_api_key(p["api_key"]),
            active=1
        ))
    db.commit()
    db.close()
    
    yield
    
    from app.audit import audit_worker
    audit_worker.flush(timeout=1.0)
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
