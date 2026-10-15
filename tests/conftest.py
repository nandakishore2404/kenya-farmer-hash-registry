import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Use a test database
os.environ["ENV"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///./test_registry.db"
os.environ["SERVER_KEY"] = "test_server_secret_rekey_key_abc123"
os.environ["ADMIN_KEY"] = "test_admin_key_super_secret"

from app.config import settings
from app.database import Base, get_db
from app.main import app, TEST_PARTNERS
from app.models import Partner
from app.hashing import hash_api_key

TEST_DB_URL = "sqlite:///./test_registry.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    # Pre-seed partners
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
    
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_registry.db"):
        try:
            os.remove("./test_registry.db")
        except Exception:
            pass

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
