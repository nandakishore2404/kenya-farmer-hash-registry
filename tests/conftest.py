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
os.environ["EVALUATOR_SHARE_K"] = "5cfa51060880d8d043bf65b215457a97ade09f39b2d00ee6de4083ee4d87c7a8"
os.environ["EVALUATOR_PEER_PUBKEYS"] = "BB+kqC5pFbFv1L9I8MRmTnZHgZUarR4P9xj19RShJhwfJYmv7p7ky34FeklakjJm1Ee/eGGihJRw7XuzzsZuc8c=,BPtkkn42JAlT3Ah13aY8vgDs2ENYr1mLcmbEfsubQUW41X2vhxuafZWZLkuF34CkI0vS6bVPp+clsW0nWRgDnqo=,BHdfWrtka5uEGxX+5+upLriDzmehz7O6hJ89oOFSqepxBUITvrauE64y3mpGmAAwhf7ray8LPDDzdl+JeWukPz0="
os.environ["EVALUATOR_AGGREGATE_PUB"] = "BMoeszozNQn0Su22c0O3pU++H8dbWINR1PVbCDispkixuohE0Q7P2N6JNy+2z4103wTOpsaoPBe8QodA1OI2g9Q="
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
