import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ["ENV"] = "development"
os.environ["EVALUATOR_SECRET_K"] = "e8c7b6a5d4c3b2a1908f7e6d5c4b3a2918273645e5d4c3b2a10987654321abcd"
os.environ["EVALUATOR_KEY_ID"] = "ke-pilot-v3"
os.environ["SERVER_KEY"] = "test_server_secret_rekey_key_abc123"
os.environ["ADMIN_KEY"] = "test_admin_key_super_secret"
os.environ["DASHBOARD_PASSWORD"] = "dev_dashboard_password"
os.environ["DATABASE_URL"] = "sqlite:///./dev_registry.db"

from app.database import Base, engine, SessionLocal
from app.models import FarmerEntity, TokenAlias, PartnerAssociation, FarmerConsent, PartnerLink, Farmer, AuditLog

db = SessionLocal()
print("Resetting dev_registry.db tables before 3,000-farmer simulation...")
db.query(AuditLog).delete()
db.query(FarmerConsent).delete()
db.query(PartnerLink).delete()
db.query(Farmer).delete()
db.query(PartnerAssociation).delete()
db.query(TokenAlias).delete()
db.query(FarmerEntity).delete()
db.commit()
db.close()

from simulator.voprf_runner import run_voprf_simulation
print("\nStarting full 3,000-Farmer Simulation into dev_registry.db...")
run_voprf_simulation(3000)

db = SessionLocal()
total_assocs = db.query(PartnerAssociation).filter(PartnerAssociation.status == "active").count()
unique_entities = db.query(FarmerEntity).filter(FarmerEntity.status == "active").count()
active_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
withdrawn_consents = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()
overlap_rate = round((1.0 - (unique_entities / total_assocs)) * 100.0, 2)

print("\n" + "="*70)
print(" 3,000-FARMER SIMULATION SUCCESSFULLY SEEDED INTO DEV_REGISTRY.DB:")
print(f" Total Active Partner Registrations: {total_assocs}")
print(f" Unique Verified Farmers:           {unique_entities}")
print(f" Cross-Partner Overlap Rate:        {overlap_rate}%")
print(f" Active Consents:                   {active_consents}")
print(f" Withdrawn Consents:                {withdrawn_consents}")
print("="*70 + "\n")
db.close()
