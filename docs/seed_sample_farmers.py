import os
import sys
import random
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

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
from app.models import Farmer, PartnerLink, Partner, FarmerEntity, TokenAlias, PartnerAssociation, FarmerConsent
from app.hashing import hash_api_key, compute_voprf_storage_digest
from sdk.python.voprf_client import OANFarmerVOPRFClient, normalise_kenyan_phone
from app.routes.evaluator import EVALUATOR_PUBLIC_KEY, EVALUATOR_SECRET_K
from app.crypto.voprf import VOPRFEngine

db = SessionLocal()

# Ensure tables
Base.metadata.create_all(bind=engine)

# Seed partners if missing
partners_data = [
    {"partner_id": "test_partner_a", "name": "One Acre Fund (Pilot A)", "api_key": "test_partner_a_api_key_2026"},
    {"partner_id": "test_partner_b", "name": "KTDA Tea Advisory (Pilot B)", "api_key": "test_partner_b_api_key_2026"},
    {"partner_id": "test_partner_c", "name": "DigiFarm Safaricom (Pilot C)", "api_key": "test_partner_c_api_key_2026"},
]

for p in partners_data:
    existing = db.query(Partner).filter(Partner.partner_id == p["partner_id"]).first()
    if not existing:
        db.add(Partner(
            partner_id=p["partner_id"],
            name=p["name"],
            api_key_hash=hash_api_key(p["api_key"]),
            active=1
        ))
db.commit()

# Sample realistic Kenyan mobile numbers
sample_numbers = [
    # Kakamega maize farmers
    ("+254 712 101 201", "F", "35-44", "37"),
    ("+254 712 101 202", "M", "45-54", "37"),
    ("+254 712 101 203", "F", "25-34", "37"),
    ("+254 712 101 204", "M", "35-44", "37"),
    ("+254 712 101 205", "F", "55-64", "37"),
    ("+254 712 101 206", "M", "25-34", "37"),
    ("+254 712 101 207", "F", "35-44", "37"),
    ("+254 712 101 208", "M", "45-54", "37"),
    
    # Nyeri tea farmers
    ("+254 722 202 301", "F", "45-54", "19"),
    ("+254 722 202 302", "M", "55-64", "19"),
    ("+254 722 202 303", "F", "35-44", "19"),
    ("+254 722 202 304", "M", "65+", "19"),
    ("+254 722 202 305", "F", "45-54", "19"),
    ("+254 722 202 306", "M", "35-44", "19"),
    ("+254 722 202 307", "F", "55-64", "19"),
    
    # Nakuru dairy & horticulture
    ("+254 733 303 401", "M", "25-34", "32"),
    ("+254 733 303 402", "F", "35-44", "32"),
    ("+254 733 303 403", "M", "18-24", "32"),
    ("+254 733 303 404", "F", "25-34", "32"),
    ("+254 733 303 405", "M", "45-54", "32"),
    ("+254 733 303 406", "F", "35-44", "32"),
    
    # Uasin Gishu grain producers
    ("+254 744 404 501", "M", "35-44", "27"),
    ("+254 744 404 502", "F", "45-54", "27"),
    ("+254 744 404 503", "M", "55-64", "27"),
    ("+254 744 404 504", "F", "25-34", "27"),
    ("+254 744 404 505", "M", "35-44", "27"),
    
    # Kiambu coffee & vegetables
    ("+254 755 505 601", "F", "35-44", "22"),
    ("+254 755 505 602", "M", "25-34", "22"),
    ("+254 755 505 603", "F", "45-54", "22"),
    ("+254 755 505 604", "M", "55-64", "22"),
    ("+254 755 505 605", "F", "25-34", "22"),
]

# Client setup
client = OANFarmerVOPRFClient(
    pilot_id="kenya-pilot",
    key_id="ke-pilot-v3",
    evaluator_public_key=EVALUATOR_PUBLIC_KEY
)

now = datetime.now(timezone.utc)
partner_ids = ["test_partner_a", "test_partner_b", "test_partner_c"]

# Clear legacy and seed sample data
db.query(PartnerLink).delete()
db.query(Farmer).delete()
db.query(PartnerAssociation).delete()
db.query(TokenAlias).delete()
db.query(FarmerConsent).delete()
db.query(FarmerEntity).delete()
db.commit()

print(f"Registering {len(sample_numbers)} sample Kenyan farmers across partners...")

registered_entities = []

for idx, (raw_phone, gender, age_band, county) in enumerate(sample_numbers):
    phone_clean = normalise_kenyan_phone(raw_phone)
    
    # VOPRF Evaluation
    x, B, r = client.prepare_blinded_registration(phone_clean)
    k_scalar = EVALUATOR_SECRET_K if isinstance(EVALUATOR_SECRET_K, int) else int(EVALUATOR_SECRET_K.get_secret_value(), 16)
    Z, proof = VOPRFEngine.evaluate(k_scalar, B, EVALUATOR_PUBLIC_KEY)
    token_bytes = client.process_evaluation_response(x, B, r, Z.to_bytes(), proof)
    
    # Create canonical entity
    entity = FarmerEntity(status="active", created_at=now - timedelta(days=random.randint(1, 30)))
    db.add(entity)
    db.flush()
    
    digest_d = compute_voprf_storage_digest("kenya-pilot", "ke-pilot-v3", token_bytes)
    db.add(TokenAlias(
        entity_id=entity.entity_id,
        digest_d=digest_d,
        pilot_id="kenya-pilot",
        scheme="voprf_secp256k1",
        key_id="ke-pilot-v3",
        status="active"
    ))
    
    # Also populate legacy Farmer model for dashboard charts
    legacy_farmer = Farmer(
        entity_id=entity.entity_id,
        hash_key=digest_d[:32],
        gender=gender,
        age_band=age_band,
        county_code=county,
        created_at=entity.created_at
    )
    db.add(legacy_farmer)
    db.flush()
    
    # Onboarder partner
    primary_partner = partner_ids[idx % len(partner_ids)]
    db.add(PartnerAssociation(
        entity_id=entity.entity_id,
        partner_id=primary_partner,
        role="onboarder",
        status="active",
        first_seen=entity.created_at
    ))
    db.add(PartnerLink(
        farmer_id=legacy_farmer.id,
        partner_id=primary_partner,
        status="active",
        received_at=entity.created_at
    ))
    
    # Active consent
    db.add(FarmerConsent(
        entity_id=entity.entity_id,
        partner_id=primary_partner,
        purpose="ADVISORY",
        status="ACTIVE",
        captured_at=entity.created_at
    ))
    
    # Overlap simulation: ~20% of farmers are registered with a second partner (e.g. KTDA + One Acre Fund)
    if idx % 5 == 0:
        secondary_partner = partner_ids[(idx + 1) % len(partner_ids)]
        db.add(PartnerAssociation(
            entity_id=entity.entity_id,
            partner_id=secondary_partner,
            role="contributor",
            status="active",
            first_seen=entity.created_at + timedelta(days=2)
        ))
        db.add(PartnerLink(
            farmer_id=legacy_farmer.id,
            partner_id=secondary_partner,
            status="active",
            received_at=entity.created_at + timedelta(days=2)
        ))
        # One farmer opts out from secondary partner
        consent_status = "WITHDRAWN" if idx == 5 else "ACTIVE"
        db.add(FarmerConsent(
            entity_id=entity.entity_id,
            partner_id=secondary_partner,
            purpose="ADVISORY",
            status=consent_status,
            captured_at=entity.created_at + timedelta(days=2)
        ))

db.commit()

# Report counts
total_reg = db.query(PartnerLink).filter(PartnerLink.status == "active").count()
unique_f = db.query(Farmer).join(PartnerLink).filter(PartnerLink.status == "active").distinct().count()
overlap = round((1.0 - (unique_f / total_reg)) * 100.0, 2)
active_c = db.query(FarmerConsent).filter(FarmerConsent.status == "ACTIVE").count()
withdrawn_c = db.query(FarmerConsent).filter(FarmerConsent.status == "WITHDRAWN").count()

print("\n" + "="*60)
print(f" SUCCESS! Sample farmers seeded into dev_registry.db:")
print(f" Total Active Partner Registrations: {total_reg}")
print(f" Unique Verified Farmers:           {unique_f}")
print(f" Cross-Partner Overlap Rate:        {overlap}%")
print(f" Active Consents:                   {active_c}")
print(f" Withdrawn Consents:                {withdrawn_c}")
print("="*60 + "\n")
db.close()
