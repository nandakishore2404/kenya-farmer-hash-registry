from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import Partner
from app.hashing import hash_api_key
from app.routes import (
    farmers_router,
    partners_router,
    admin_router,
    dashboard_router,
    dev_router,
    evaluator_router,
    consent_router
)

TEST_PARTNERS = [
    {"partner_id": "test_partner_a", "name": "Test Partner A", "api_key": "test_partner_a_api_key_2026"},
    {"partner_id": "test_partner_b", "name": "Test Partner B", "api_key": "test_partner_b_api_key_2026"},
    {"partner_id": "test_partner_c", "name": "Test Partner C", "api_key": "test_partner_c_api_key_2026"},
]

def init_db():
    Base.metadata.create_all(bind=engine)
    if settings.ENV == "development" and settings.SEED_TEST_PARTNERS:
        db = SessionLocal()
        try:
            for p in TEST_PARTNERS:
                existing = db.query(Partner).filter(Partner.partner_id == p["partner_id"]).first()
                if not existing:
                    partner = Partner(
                        partner_id=p["partner_id"],
                        name=p["name"],
                        api_key_hash=hash_api_key(p["api_key"]),
                        active=1
                    )
                    db.add(partner)
            db.commit()
        finally:
            db.close()

    if settings.ENV == "development":
        print("\n" + "=" * 72)
        print(" KENYA FARMER HASH REGISTRY - LOCAL DEVELOPMENT ENVIRONMENT")
        print("=" * 72)
        print(" Registry URL:    http://localhost:8008")
        print(" Dashboard URL:   http://localhost:8008/dashboard")
        print(" Test Console:    http://localhost:8008/dev/console")
        print(" Health Check:    http://localhost:8008/health")
        print("-" * 72)
        print(f" Dashboard Login: {settings.DASHBOARD_USER} / [configured via DASHBOARD_PASSWORD]")
        print("-" * 72)
        print(" Seeded Test Partners:")
        print("   1. ID: test_partner_a (Test Partner A)")
        print("      API Key: test_partner_a_api_key_2026")
        print("   2. ID: test_partner_b (Test Partner B)")
        print("      API Key: test_partner_b_api_key_2026")
        print("   3. ID: test_partner_c (Test Partner C - CSV)")
        print("      API Key: test_partner_c_api_key_2026")
        print("-" * 72)
        print(" Shared Pilot Key: partner_shared_pilot_secret")
        print("=" * 72 + "\n")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from app.audit import audit_worker
    audit_worker.start()
    yield
    audit_worker.stop(flush=True)

app = FastAPI(
    title=settings.APP_NAME,
    description="Privacy-Preserving Farmer Hash Registry for Agricultural Advisory Pilots in Kenya",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(farmers_router)
app.include_router(partners_router)
app.include_router(admin_router)
app.include_router(dashboard_router)
app.include_router(dev_router)
app.include_router(evaluator_router)
app.include_router(consent_router)

@app.get("/health")
def health_check():
    return {"status": "ok", "app": settings.APP_NAME}

