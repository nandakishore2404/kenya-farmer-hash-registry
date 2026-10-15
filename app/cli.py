import argparse
import sys
import secrets
from app.database import SessionLocal, init_db as db_init
from app.models import Partner
from app.hashing import hash_api_key

def add_partner(partner_id: str, name: str):
    db = SessionLocal()
    try:
        existing = db.query(Partner).filter(Partner.partner_id == partner_id).first()
        if existing:
            print(f"Error: Partner '{partner_id}' already exists.", file=sys.stderr)
            sys.exit(1)
            
        api_key = f"{partner_id}_key_{secrets.token_hex(16)}"
        api_key_hash = hash_api_key(api_key)
        
        partner = Partner(
            partner_id=partner_id,
            name=name,
            api_key_hash=api_key_hash,
            active=1
        )
        db.add(partner)
        db.commit()
        
        print("\n=======================================================")
        print(f"  PARTNER ONBOARDED SUCCESSFULLY")
        print("=======================================================")
        print(f"Partner ID:   {partner_id}")
        print(f"Partner Name: {name}")
        print(f"Status:       Active")
        print(f"API Key:      {api_key}")
        print("-------------------------------------------------------")
        print("IMPORTANT: Share this API Key securely with the partner.")
        print("It will NOT be shown again. The registry stores only its SHA-256 hash.")
        print("=======================================================\n")
    finally:
        db.close()

def list_partners():
    db = SessionLocal()
    try:
        partners = db.query(Partner).order_by(Partner.partner_id.asc()).all()
        print("\n=======================================================")
        print(f"  REGISTERED DELIVERY PARTNERS ({len(partners)} total)")
        print("=======================================================")
        print(f"{'Partner ID':<20} | {'Name':<30} | {'Status':<10}")
        print("-" * 66)
        for p in partners:
            status = "Active" if p.active == 1 else "Disabled"
            print(f"{p.partner_id:<20} | {p.name:<30} | {status:<10}")
        print("=======================================================\n")
    finally:
        db.close()

def disable_partner(partner_id: str):
    db = SessionLocal()
    try:
        partner = db.query(Partner).filter(Partner.partner_id == partner_id).first()
        if not partner:
            print(f"Error: Partner '{partner_id}' not found.", file=sys.stderr)
            sys.exit(1)
        partner.active = 0
        db.commit()
        print(f"Partner '{partner_id}' ({partner.name}) has been disabled.")
    finally:
        db.close()

def main():
    parser = argparse.ArgumentParser(description="Farmer Hash Registry Partner Administration CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # add-partner
    p_add = subparsers.add_parser("add-partner", help="Onboard a new delivery partner")
    p_add.add_argument("--id", required=True, help="Unique partner ID (e.g. partner_a)")
    p_add.add_argument("--name", required=True, help="Display organisation name (e.g. 'Partner A')")
    
    # list-partners
    subparsers.add_parser("list-partners", help="List all registered delivery partners")
    
    # disable-partner
    p_dis = subparsers.add_parser("disable-partner", help="Disable a delivery partner")
    p_dis.add_argument("--id", required=True, help="Partner ID to disable")
    
    args = parser.parse_args()
    
    if args.command == "add-partner":
        add_partner(args.id, args.name)
    elif args.command == "list-partners":
        list_partners()
    elif args.command == "disable-partner":
        disable_partner(args.id)

if __name__ == "__main__":
    main()
