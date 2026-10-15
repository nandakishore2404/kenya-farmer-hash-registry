from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import Partner
from app.hashing import hash_api_key
from app.routes import farmers_router, partners_router, admin_router, dashboard_router

DEFAULT_PARTNERS = [
    {"partner_id": "partner_alpha", "name": "DigiFarm Kenya", "api_key": "alpha_api_key_pilot_2026"},
    {"partner_id": "partner_beta", "name": "One Acre Fund", "api_key": "beta_api_key_pilot_2026"},
    {"partner_id": "partner_gamma", "name": "KALRO Advisory", "api_key": "gamma_api_key_pilot_2026"},
]

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for p in DEFAULT_PARTNERS:
            existing = db.query(Partner).filter(Partner.partner_id == p["partner_id"]).first()
            if not existing:
                partner = Partner(
                    partner_id=p["partner_id"],
                    name=p["name"],
                    api_key_hash=hash_api_key(p["api_key"])
                )
                db.add(partner)
        db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

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

@app.get("/health")
def health_check():
    return {"status": "ok", "app": settings.APP_NAME}
